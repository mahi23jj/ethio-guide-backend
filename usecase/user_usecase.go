package usecase

import (
	"EthioGuide/domain"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

type UserUsecase struct {
	userRepo           domain.IAccountRepository
	userPreferenceRepo domain.IPreferencesRepository
	tokenRepo          domain.ITokenRepository
	passwordService    domain.IPasswordService
	jwtService         domain.IJWTService
	googleService      domain.IGoogleOAuthService
	emailService       domain.IEmailService
	contextTimeout     time.Duration
}

func NewUserUsecase(
	ur domain.IAccountRepository,
	up domain.IPreferencesRepository,
	tr domain.ITokenRepository,
	ps domain.IPasswordService,
	js domain.IJWTService,
	gs domain.IGoogleOAuthService,
	es domain.IEmailService,
	timeout time.Duration,
) domain.IUserUsecase {
	return &UserUsecase{
		userRepo:           ur,
		userPreferenceRepo: up,
		tokenRepo:          tr,
		passwordService:    ps,
		jwtService:         js,
		googleService:      gs,
		emailService:       es,
		contextTimeout:     timeout,
	}
}

func (uc *UserUsecase) Register(c context.Context, user *domain.Account) error {
	ctx, cancel := context.WithTimeout(c, uc.contextTimeout)
	defer cancel()

	if _, err := mail.ParseAddress(user.Email); err != nil {
		return domain.ErrInvalidEmailFormat
	}
	if len(user.PasswordHash) < 8 {
		return domain.ErrPasswordTooShort
	}
	if strings.TrimSpace(user.UserDetail.Username) == "" {
		return domain.ErrUsernameEmpty
	}

	_, err := uc.userRepo.GetByEmail(ctx, user.Email)
	if err == nil {
		return domain.ErrEmailExists
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("error checking email existence: %w", err)
	}

	_, err = uc.userRepo.GetByUsername(ctx, user.UserDetail.Username)
	if err == nil {
		return domain.ErrUsernameExists
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("error checking username existence: %w", err)
	}

	hashedPassword, err := uc.passwordService.HashPassword(user.PasswordHash)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	user.PasswordHash = hashedPassword
	user.Role = domain.RoleUser
	user.UserDetail.IsVerified = true // Demo deployment: accounts are auto-verified after registration.
	user.AuthProvider = domain.AuthProviderLocal

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("failed to create user in repository: %w", err)
	}

	preference := &domain.Preferences{
		UserID:            user.ID,
		PreferredLang:     domain.English,
		PushNotification:  false,
		EmailNotification: false,
	}

	if err = uc.userPreferenceRepo.Create(ctx, preference); err != nil {
		return err
	}

	// Email verification is temporarily disabled for the demo deployment.
	// Re-enable this block when verification should be required again.
	// if err = uc.sendVerificationEmail(ctx, user); err != nil {
	// 	return err
	// }

	return nil
}

func (uc *UserUsecase) sendVerificationEmail(ctx context.Context, user *domain.Account) error {
	if user.UserDetail.IsVerified {
		return domain.ErrUserAlreadyVerified
	}

	activationToken, activateclaim, errToken := uc.jwtService.GenerateUtilityToken(user.ID)
	if errToken != nil {
		return errToken
	}

	activateToken := domain.Token{
		Id:        activateclaim.ID,
		Token:     activationToken,
		TokenType: domain.VerificationToken,
		ExpiresAt: activateclaim.ExpiresAt.Time,
	}

	if _, err := uc.tokenRepo.CreateToken(ctx, &activateToken); err != nil {
		return err
	}

	go func() {
		err := uc.emailService.SendVerificationEmail(user.Email, user.UserDetail.Username, activationToken)
		if err != nil {
			fmt.Printf("Failed to send activation email: %v\n", err)
		}
	}()

	return nil
}

func (uc *UserUsecase) VerifyAccount(ctx context.Context, activationTokenValue string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	claims, err := uc.jwtService.ValidateToken(activationTokenValue)
	if err != nil {
		return domain.ErrInvalidActivationToken
	}

	if _, err := uc.tokenRepo.GetToken(ctx, string(domain.VerificationToken), claims.ID); err != nil {
		return domain.ErrInvalidActivationToken
	}

	_, errUser := uc.userRepo.GetById(ctx, claims.UserID)
	if errUser != nil {
		return domain.ErrUserNotFound
	}

	update := map[string]interface{}{
		"user_detail.is_verified": true,
	}

	errUpdate := uc.userRepo.UpdateUserFields(ctx, claims.UserID, update)
	if errUpdate != nil {
		return errUpdate
	}

	return nil
}

// Login method is already quite good. Minimal changes for consistency.
func (uc *UserUsecase) Login(c context.Context, identifier, password string) (*domain.Account, string, string, error) {
	ctx, cancel := context.WithTimeout(c, uc.contextTimeout)
	defer cancel()

	var account *domain.Account
	var err error

	if _, mailErr := mail.ParseAddress(identifier); mailErr == nil {
		account, err = uc.userRepo.GetByEmail(ctx, identifier)
		// } else if result, _ := regexp.MatchString(`^\+?[0-9]{8,14}$`, identifier); result {
		// 	account, err = uc.userRepo.GetByPhoneNumber(ctx, identifier)
	} else {
		account, err = uc.userRepo.GetByUsername(ctx, identifier)
	}

	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, "", "", domain.ErrAuthenticationFailed
		}
		return nil, "", "", fmt.Errorf("repository error during login: %w", err)
	}

	if account.Role == domain.RoleUser {
		if !account.UserDetail.IsVerified {
			if err = uc.sendVerificationEmail(ctx, account); err != nil {
				return nil, "", "", err
			}
			return nil, "", "", domain.ErrAccountNotActive
		}
	}

	err = uc.passwordService.ComparePassword(account.PasswordHash, password)
	if err != nil {
		return nil, "", "", domain.ErrAuthenticationFailed
	}

	accessToken, _, err := uc.jwtService.GenerateAccessToken(account.ID, account.Role)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshClaims, err := uc.jwtService.GenerateRefreshToken(account.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenToSave := &domain.Token{
		Id:        refreshClaims.ID,
		Token:     refreshToken,
		TokenType: domain.RefreshToken,
		ExpiresAt: refreshClaims.ExpiresAt.Time,
	}

	// Save the token to the repository
	if _, err := uc.tokenRepo.CreateToken(ctx, tokenToSave); err != nil {
		// This is a critical error, as login succeeds but refresh will fail.
		return nil, "", "", fmt.Errorf("CRITICAL: failed to store refresh token after login: %w", err)
	}

	return account, accessToken, refreshToken, nil
}

func (uc *UserUsecase) RefreshTokenForWeb(ctx context.Context, refreshToken string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	claims, err := uc.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if the token exists in our database (it hasn't been revoked/logged out).
	// We use the token's unique ID (JTI) to look it up.
	_, err = uc.tokenRepo.GetToken(ctx, string(domain.RefreshToken), claims.ID)
	if err != nil {
		// If the token is not found in the repo, it's invalid, even if the signature is okay.
		return "", domain.ErrAuthenticationFailed
	}

	newAccessToken, _, err := uc.jwtService.GenerateAccessToken(claims.UserID, claims.Role)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return newAccessToken, nil
}

func (uc *UserUsecase) RefreshTokenForMobile(ctx context.Context, refreshToken string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	claims, err := uc.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Atomically find and delete the token. This prevents race conditions.
	// If your ITokenRepository can't do this atomically, a check-then-delete is the next best.
	// We assume DeleteToken fails if the token doesn't exist.
	err = uc.tokenRepo.DeleteToken(ctx, string(domain.RefreshToken), claims.ID)
	if err != nil {
		// This error means the token was not found or a DB error occurred.
		// In either case, it's an authentication failure.
		return "", "", domain.ErrAuthenticationFailed
	}

	newAccessToken, _, err := uc.jwtService.GenerateAccessToken(claims.UserID, claims.Role)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefreshToken, refreshClaims, err := uc.jwtService.GenerateRefreshToken(claims.UserID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	tokenToSave := &domain.Token{
		Id:        refreshClaims.ID, // Use the new token's ID
		Token:     newRefreshToken,
		TokenType: domain.RefreshToken,
		ExpiresAt: refreshClaims.ExpiresAt.Time,
	}
	if _, err := uc.tokenRepo.CreateToken(ctx, tokenToSave); err != nil {
		return "", "", fmt.Errorf("CRITICAL: failed to store new refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}

func (uc *UserUsecase) GetProfile(c context.Context, userID string) (*domain.Account, error) {
	ctx, cancel := context.WithTimeout(c, uc.contextTimeout)
	defer cancel()

	account, err := uc.userRepo.GetById(ctx, userID)
	if err != nil || account == nil {
		return nil, domain.ErrUserNotFound

	}

	return account, nil
}

func (uc *UserUsecase) UpdatePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	account, err := uc.userRepo.GetById(ctx, userID)
	if err != nil || account == nil {
		return domain.ErrUserNotFound
	}

	err = uc.passwordService.ComparePassword(account.PasswordHash, currentPassword)
	if err != nil {
		return domain.ErrAuthenticationFailed
	}

	if len(newPassword) < 8 {
		return domain.ErrPasswordTooShort
	}

	hashedNewPassword, err := uc.passwordService.HashPassword(newPassword)
	if err != nil {
		return err
	}

	err = uc.userRepo.UpdatePassword(ctx, userID, hashedNewPassword)
	if err != nil {
		return err
	}
	return nil
}

func (uc *UserUsecase) LoginWithSocial(ctx context.Context, provider domain.AuthProvider, code string) (*domain.Account, string, string, error) {
	switch provider {
	case domain.AuthProviderGoogle:
		return uc.loginWithGoogle(ctx, code)
	// case "facebook":
	//     return uc.loginWithFacebook(ctx, code)
	default:
		return nil, "", "", domain.ErrInvalidProvider
	}
}

func (uc *UserUsecase) loginWithGoogle(ctx context.Context, code string) (*domain.Account, string, string, error) {
	// Step 1: Exchange the code for a token using the service
	googleToken, err := uc.googleService.ExchangeCodeForToken(ctx, code)
	if err != nil {
		return nil, "", "", err
	}

	// Step 2: Get user information using the token via the service
	userInfo, err := uc.googleService.GetUserInfo(ctx, googleToken)
	if err != nil {
		return nil, "", "", err
	}

	if userInfo.Email == "" {
		return nil, "", "", domain.ErrAuthenticationFailed
	}

	user, err := uc.userRepo.GetByEmail(ctx, userInfo.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) || errors.Is(err, domain.ErrNotFound) {
			// Create a new user if they don't exist
			newUser := &domain.Account{
				Email:         userInfo.Email,
				Role:          domain.RoleUser,
				AuthProvider:  domain.AuthProviderGoogle,
				ProviderID:    userInfo.ID,
				CreatedAt:     time.Now().UTC(),
				Name:          userInfo.Name,
				ProfilePicURL: userInfo.ProfilePictureURL,
				UserDetail: &domain.UserDetail{
					Username:         userInfo.Email, // Default username to email
					SubscriptionPlan: domain.SubscriptionNone,
					IsVerified:       true, // Google accounts are considered verified
					IsBanned:         false,
				},
			}

			if err := uc.userRepo.Create(ctx, newUser); err != nil {
				return nil, "", "", fmt.Errorf("failed to create user from google login: %w", err)
			}
			user = newUser

		} else {
			return nil, "", "", fmt.Errorf("database error while fetching user: %w", err)
		}
	} else if user.AuthProvider != domain.AuthProviderGoogle && user.AuthProvider != domain.AuthProviderLocal {
		return nil, "", "", domain.ErrConflict
	}

	accessToken, _, err := uc.jwtService.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshClaims, err := uc.jwtService.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenToSave := &domain.Token{
		Id:        refreshClaims.ID,
		Token:     refreshToken,
		TokenType: domain.RefreshToken,
		ExpiresAt: refreshClaims.ExpiresAt.Time,
	}

	if _, err := uc.tokenRepo.CreateToken(ctx, tokenToSave); err != nil {
		return nil, "", "", fmt.Errorf("CRITICAL: failed to store refresh token after login: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

func (uc *UserUsecase) UpdateProfile(ctx context.Context, account *domain.Account) (*domain.Account, error) {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	// --- validation rules ---
	if account.UserDetail != nil && account.OrganizationDetail != nil {
		return nil, domain.ErrConflict
	}

	exists, err := uc.userRepo.ExistsByEmail(ctx, account.Email, account.ID)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	exists, err = uc.userRepo.ExistsByUsername(ctx, account.UserDetail.Username, account.ID)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrEmailExists
	}

	// --- persist ---
	if err := uc.userRepo.UpdateProfile(ctx, *account); err != nil {
		return nil, err
	}

	return account, nil
}

func (uc *UserUsecase) Logout(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()
	err := uc.tokenRepo.DeleteToken(ctx, string(domain.RefreshToken), userID)
	if err != nil {
		return fmt.Errorf("failed to logout user: %w", err)
	}
	return nil
}

func (uc *UserUsecase) ForgetPassword(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	user, err := uc.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	passwordString, passwordclaim, err := uc.jwtService.GenerateUtilityToken(user.ID)
	if err != nil {
		return err
	}

	passwordToken := domain.Token{
		Id:        passwordclaim.ID,
		Token:     passwordString,
		TokenType: domain.ResetPasswordToken,
		ExpiresAt: passwordclaim.ExpiresAt.Time,
	}

	if _, err := uc.tokenRepo.CreateToken(ctx, &passwordToken); err != nil {
		return err
	}

	go func() {
		err := uc.emailService.SendPasswordResetEmail(user.Email, user.UserDetail.Username, passwordString)
		if err != nil {
			fmt.Printf("Failed to send password reset email: %v\n", err)
		}
	}()

	return nil
}

func (uc *UserUsecase) ResetPassword(ctx context.Context, resetToken, newPassword string) error {
	if resetToken == "" || newPassword == "" {
		return fmt.Errorf("empty field")
	}

	if len(newPassword) < 8 {
		return domain.ErrPasswordTooShort
	}

	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	claims, err := uc.jwtService.ValidateToken(resetToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	if _, err := uc.tokenRepo.GetToken(ctx, string(domain.ResetPasswordToken), claims.ID); err != nil {
		return domain.ErrInvalidResetToken
	}

	hashedNewPassword, _ := uc.passwordService.HashPassword(newPassword)
	update := map[string]interface{}{
		"password_hash": hashedNewPassword,
	}

	if err := uc.userRepo.UpdateUserFields(ctx, claims.UserID, update); err != nil {
		return err
	}

	if err := uc.tokenRepo.DeleteToken(ctx, string(domain.ResetPasswordToken), claims.ID); err != nil {
		return err
	}

	return nil
}

func (uc *UserUsecase) RegisterOrg(ctx context.Context, Name, Email, OrgType string) error {
	if Name == "" || Email == "" || OrgType == "" {
		return fmt.Errorf("empty field")
	}

	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	if _, err := mail.ParseAddress(Email); err != nil {
		return domain.ErrInvalidEmailFormat
	}

	_, err := uc.userRepo.GetByEmail(ctx, Email)
	if err == nil {
		return domain.ErrEmailExists
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("error checking email existence: %w", err)
	}
	hashedPassword, err := uc.passwordService.HashPassword("defaultPassword123")
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	orgAccount := domain.Account{
		Name:          Name,
		Email:         Email,
		Role:          domain.RoleOrg,
		PasswordHash:  hashedPassword,
		ProfilePicURL: "https://res.cloudinary.com/dmcsjc9yv/image/upload/v1757316658/placeholder_jereof.jpg",
		OrganizationDetail: &domain.OrganizationDetail{
			Type: domain.OrganizationType(OrgType),
		},
	}

	if err := uc.userRepo.Create(ctx, &orgAccount); err != nil {
		return fmt.Errorf("failed to create user in repository: %w", err)
	}

	return nil
}

func (uc *UserUsecase) GetOrgs(ctx context.Context, filter domain.GetOrgsFilter) ([]*domain.Account, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	if filter.Page <= 0 {
		filter.Page = 1
	}

	if filter.PageSize <= 0 {
		filter.PageSize = 1
	}

	return uc.userRepo.GetOrgs(ctx, filter)
}

func (uc *UserUsecase) GetOrgById(ctx context.Context, orgId string) (*domain.Account, error) {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	if orgId == "" {
		return nil, domain.ErrInvalidID
	}

	return uc.userRepo.GetById(ctx, orgId)
}

func (uc *UserUsecase) UpdateOrgFields(ctx context.Context, orgId string, update map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, uc.contextTimeout)
	defer cancel()

	if orgId == "" {
		return domain.ErrInvalidID
	}

	return uc.userRepo.UpdateUserFields(ctx, orgId, update)
}
