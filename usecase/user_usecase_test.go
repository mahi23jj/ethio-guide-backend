package usecase_test

import (
	"EthioGuide/domain"
	. "EthioGuide/usecase"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
)

// --- Mocks for All Dependencies ---

type MockAccountRepository struct{ mock.Mock }

func (m *MockAccountRepository) Create(ctx context.Context, user *domain.Account) error {
	return m.Called(ctx, user).Error(0)
}
func (m *MockAccountRepository) GetById(ctx context.Context, id string) (*domain.Account, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}
func (m *MockAccountRepository) GetByEmail(ctx context.Context, email string) (*domain.Account, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}
func (m *MockAccountRepository) GetByUsername(ctx context.Context, username string) (*domain.Account, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Account), args.Error(1)
}
func (m *MockAccountRepository) GetOrgs(ctx context.Context, filter domain.GetOrgsFilter) ([]*domain.Account, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.Account), args.Get(1).(int64), args.Error(2)
}
func (m *MockAccountRepository) UpdatePassword(ctx context.Context, accountID, newPassword string) error {
	return m.Called(ctx, accountID, newPassword).Error(0)
}
func (m *MockAccountRepository) UpdateProfile(ctx context.Context, account domain.Account) error {
	return m.Called(ctx, account).Error(0)
}
func (m *MockAccountRepository) ExistsByEmail(ctx context.Context, email, excludeID string) (bool, error) {
	args := m.Called(ctx, email, excludeID)
	return args.Bool(0), args.Error(1)
}
func (m *MockAccountRepository) ExistsByUsername(ctx context.Context, username, excludeID string) (bool, error) {
	args := m.Called(ctx, username, excludeID)
	return args.Bool(0), args.Error(1)
}
func (m *MockAccountRepository) UpdateUserFields(ctx context.Context, userIDstr string, update map[string]interface{}) error {
	return m.Called(ctx, userIDstr, update).Error(0)
}

type MockTokenRepository struct{ mock.Mock }

func (m *MockTokenRepository) CreateToken(ctx context.Context, token *domain.Token) (*domain.Token, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Token), args.Error(1)
}
func (m *MockTokenRepository) GetToken(ctx context.Context, tokentype, token string) (string, error) {
	args := m.Called(ctx, tokentype, token)
	return args.String(0), args.Error(1)
}
func (m *MockTokenRepository) DeleteToken(ctx context.Context, tokentype, token string) error {
	return m.Called(ctx, tokentype, token).Error(0)
}

type MockPasswordService struct{ mock.Mock }

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordService) ComparePassword(hashedPassword, password string) error {
	return m.Called(hashedPassword, password).Error(0)
}

type MockJWTService struct{ mock.Mock }

func (m *MockJWTService) GenerateAccessToken(userID string, role domain.Role) (string, *domain.JWTClaims, error) {
	args := m.Called(userID, role)
	if args.Get(1) == nil {
		return args.String(0), nil, args.Error(2)
	}
	return args.String(0), args.Get(1).(*domain.JWTClaims), args.Error(2)
}
func (m *MockJWTService) GenerateRefreshToken(userID string) (string, *domain.JWTClaims, error) {
	args := m.Called(userID)
	if args.Get(1) == nil {
		return args.String(0), nil, args.Error(2)
	}
	return args.String(0), args.Get(1).(*domain.JWTClaims), args.Error(2)
}
func (m *MockJWTService) ValidateToken(tokenString string) (*domain.JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.JWTClaims), args.Error(1)
}
func (m *MockJWTService) ParseExpiredToken(tokenString string) (*domain.JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.JWTClaims), args.Error(1)
}
func (m *MockJWTService) GetRefreshTokenExpiry() time.Duration {
	return m.Called().Get(0).(time.Duration)
}
func (m *MockJWTService) GenerateUtilityToken(userID string) (string, *domain.JWTClaims, error) {
	args := m.Called(userID)
	if args.Get(1) == nil {
		return args.String(0), nil, args.Error(2)
	}
	return args.String(0), args.Get(1).(*domain.JWTClaims), args.Error(2)
}

type MockGoogleOAuthService struct{ mock.Mock }

func (m *MockGoogleOAuthService) ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth2.Token), args.Error(1)
}
func (m *MockGoogleOAuthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*domain.GoogleUserInfo, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.GoogleUserInfo), args.Error(1)
}

type MockEmailService struct {
	mock.Mock
	Wg *sync.WaitGroup // Add a WaitGroup
}

func (m *MockEmailService) SendPasswordResetEmail(to, user, token string) error {
	defer m.Wg.Done()
	args := m.Called(to, user, token)
	return args.Error(0)
}

func (m *MockEmailService) SendVerificationEmail(to, user, token string) error {
	defer m.Wg.Done()
	args := m.Called(to, user, token)
	return args.Error(0)
}

// --- Test Suite ---
type UserUsecaseTestSuite struct {
	suite.Suite
	mockUserRepo  *MockAccountRepository
	mockPrefRepo  *MockPreferencesRepository
	mockTokenRepo *MockTokenRepository
	mockPassSvc   *MockPasswordService
	mockJWTSvc    *MockJWTService
	mockGoogleSvc *MockGoogleOAuthService
	mockEmailSvc  *MockEmailService
	usecase       domain.IUserUsecase
	ctx           context.Context
}

func (s *UserUsecaseTestSuite) SetupTest() {
	s.mockUserRepo = new(MockAccountRepository)
	s.mockPrefRepo = new(MockPreferencesRepository)
	s.mockTokenRepo = new(MockTokenRepository)
	s.mockPassSvc = new(MockPasswordService)
	s.mockJWTSvc = new(MockJWTService)
	s.mockGoogleSvc = new(MockGoogleOAuthService)
	s.mockEmailSvc = new(MockEmailService)
	s.mockEmailSvc.Wg = new(sync.WaitGroup)
	s.usecase = NewUserUsecase(
		s.mockUserRepo,
		s.mockPrefRepo,
		s.mockTokenRepo,
		s.mockPassSvc,
		s.mockJWTSvc,
		s.mockGoogleSvc,
		s.mockEmailSvc,
		5*time.Second,
	)
	s.ctx = context.Background()
}

func TestUserUsecaseTestSuite(t *testing.T) {
	suite.Run(t, new(UserUsecaseTestSuite))
}

// --- Tests ---

func (s *UserUsecaseTestSuite) TestRegister_Success() {
	// Arrange
	user := &domain.Account{Email: "test@example.com", PasswordHash: "password123", UserDetail: &domain.UserDetail{Username: "tester"}}
	s.mockUserRepo.On("GetByEmail", mock.Anything, user.Email).Return(nil, domain.ErrNotFound).Once()
	s.mockUserRepo.On("GetByUsername", mock.Anything, user.UserDetail.Username).Return(nil, domain.ErrNotFound).Once()
	s.mockPassSvc.On("HashPassword", "password123").Return("hashed_password", nil).Once()
	s.mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(account *domain.Account) bool {
		return account.UserDetail != nil && account.UserDetail.IsVerified && account.AuthProvider == domain.AuthProviderLocal && account.Role == domain.RoleUser
	})).Return(nil).Once()
	s.mockPrefRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.Preferences")).Return(nil).Once()
	// Act
	err := s.usecase.Register(s.ctx, user)

	// Assert
	s.NoError(err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertExpectations(s.T())
	s.mockPrefRepo.AssertExpectations(s.T())
	s.mockJWTSvc.AssertNotCalled(s.T(), "GenerateUtilityToken", mock.Anything)
	s.mockTokenRepo.AssertNotCalled(s.T(), "CreateToken", mock.Anything, mock.Anything)
	s.mockEmailSvc.AssertNotCalled(s.T(), "SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything)
}

func (s *UserUsecaseTestSuite) TestRegister_EmailExists() {
	// Arrange
	user := &domain.Account{Email: "exists@example.com", PasswordHash: "password123", UserDetail: &domain.UserDetail{Username: "tester"}}
	s.mockUserRepo.On("GetByEmail", mock.Anything, user.Email).Return(&domain.Account{}, nil).Once() // User found

	// Act
	err := s.usecase.Register(s.ctx, user)

	// Assert
	s.ErrorIs(err, domain.ErrEmailExists)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertNotCalled(s.T(), "HashPassword") // Should not be called
}

func (s *UserUsecaseTestSuite) TestVerifyAccount_Success() {
	// Arrange
	token := "valid-token"
	claims := &domain.JWTClaims{UserID: "user-1", RegisteredClaims: jwt.RegisteredClaims{ID: "jti-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}
	s.mockJWTSvc.On("ValidateToken", token).Return(claims, nil).Once()
	s.mockTokenRepo.On("GetToken", mock.Anything, string(domain.VerificationToken), "jti-1").Return("jti-1", nil).Once()
	s.mockUserRepo.On("GetById", mock.Anything, "user-1").Return(&domain.Account{}, nil).Once()
	s.mockUserRepo.On("UpdateUserFields", mock.Anything, "user-1", mock.Anything).Return(nil).Once()

	// Act
	err := s.usecase.VerifyAccount(s.ctx, token)

	// Assert
	s.NoError(err)
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestLogin_Success() {
	// Arrange
	identifier := "test@example.com"
	password := "password123"
	account := &domain.Account{ID: "user-1", PasswordHash: "hashed", Role: domain.RoleUser, UserDetail: &domain.UserDetail{IsVerified: true}}
	refreshClaims := &domain.JWTClaims{RegisteredClaims: jwt.RegisteredClaims{ID: "refresh-jti", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}

	s.mockUserRepo.On("GetByEmail", mock.Anything, identifier).Return(account, nil).Once()
	s.mockPassSvc.On("ComparePassword", "hashed", password).Return(nil).Once()
	s.mockJWTSvc.On("GenerateAccessToken", "user-1", domain.RoleUser).Return("access-token", &domain.JWTClaims{}, nil).Once()
	s.mockJWTSvc.On("GenerateRefreshToken", "user-1").Return("refresh-token", refreshClaims, nil).Once()
	s.mockTokenRepo.On("CreateToken", mock.Anything, mock.AnythingOfType("*domain.Token")).Return(&domain.Token{}, nil).Once()

	// Act
	resAccount, accessToken, refreshToken, err := s.usecase.Login(s.ctx, identifier, password)

	// Assert
	s.NoError(err)
	s.Equal(account, resAccount)
	s.Equal("access-token", accessToken)
	s.Equal("refresh-token", refreshToken)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertExpectations(s.T())
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestLogin_UnverifiedUser() {
	// Arrange
	account := &domain.Account{ID: "user-1", Email: "unverified@test.com", Role: domain.RoleUser, UserDetail: &domain.UserDetail{IsVerified: false}}
	utilityClaims := &domain.JWTClaims{RegisteredClaims: jwt.RegisteredClaims{ID: "token-id", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}

	s.mockUserRepo.On("GetByEmail", mock.Anything, account.Email).Return(account, nil).Once()
	s.mockPassSvc.On("ComparePassword", mock.Anything, mock.Anything).Return(nil).Once() // Assume password is correct
	// Expect a new verification email to be sent
	s.mockJWTSvc.On("GenerateUtilityToken", account.ID).Return("utility-token", utilityClaims, nil).Once()
	s.mockTokenRepo.On("CreateToken", mock.Anything, mock.AnythingOfType("*domain.Token")).Return(&domain.Token{}, nil).Once()
	s.mockEmailSvc.Wg.Add(1)
	s.mockEmailSvc.On("SendVerificationEmail", account.Email, account.UserDetail.Username, "utility-token").Return(nil).Once()
	// Act
	_, _, _, err := s.usecase.Login(s.ctx, account.Email, "password")
	s.mockEmailSvc.Wg.Wait()

	// Assert
	s.ErrorIs(err, domain.ErrAccountNotActive)
	s.mockEmailSvc.AssertExpectations(s.T()) // Verify that the email was sent
}

func (s *UserUsecaseTestSuite) TestRefreshTokenForWeb_Success() {
	// Arrange
	refreshToken := "valid-refresh-token"
	claims := &domain.JWTClaims{UserID: "user-1", Role: domain.RoleUser, RegisteredClaims: jwt.RegisteredClaims{ID: "jti-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}
	s.mockJWTSvc.On("ValidateToken", refreshToken).Return(claims, nil).Once()
	s.mockTokenRepo.On("GetToken", mock.Anything, string(domain.RefreshToken), "jti-1").Return("jti-1", nil).Once()
	s.mockJWTSvc.On("GenerateAccessToken", "user-1", domain.RoleUser).Return("new-access-token", &domain.JWTClaims{}, nil).Once()

	// Act
	newAccessToken, err := s.usecase.RefreshTokenForWeb(s.ctx, refreshToken)

	// Assert
	s.NoError(err)
	s.Equal("new-access-token", newAccessToken)
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestRefreshTokenForMobile_Success() {
	// Arrange
	refreshToken := "valid-refresh-token"
	claims := &domain.JWTClaims{UserID: "user-1", RegisteredClaims: jwt.RegisteredClaims{ID: "jti-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}, Role: domain.RoleUser}
	newRefreshClaims := &domain.JWTClaims{RegisteredClaims: jwt.RegisteredClaims{ID: "jti-2", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}

	s.mockJWTSvc.On("ValidateToken", refreshToken).Return(claims, nil).Once()
	s.mockTokenRepo.On("DeleteToken", mock.Anything, string(domain.RefreshToken), "jti-1").Return(nil).Once()
	s.mockJWTSvc.On("GenerateAccessToken", "user-1", domain.RoleUser).Return("new-access-token", &domain.JWTClaims{}, nil).Once()
	s.mockJWTSvc.On("GenerateRefreshToken", "user-1").Return("new-refresh-token", newRefreshClaims, nil).Once()
	s.mockTokenRepo.On("CreateToken", mock.Anything, mock.AnythingOfType("*domain.Token")).Return(&domain.Token{}, nil).Once()

	// Act
	newAccess, newRefresh, err := s.usecase.RefreshTokenForMobile(s.ctx, refreshToken)

	// Assert
	s.NoError(err)
	s.Equal("new-access-token", newAccess)
	s.Equal("new-refresh-token", newRefresh)
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestGetProfile_Success() {
	// Arrange
	userID := "user-123"
	expectedAccount := &domain.Account{ID: userID, Name: "Test User"}
	s.mockUserRepo.On("GetById", mock.Anything, userID).Return(expectedAccount, nil).Once()

	// Act
	account, err := s.usecase.GetProfile(s.ctx, userID)

	// Assert
	s.NoError(err)
	s.Equal(expectedAccount, account)
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestUpdatePassword_Success() {
	// Arrange
	userID, oldPass, newPass := "user-1", "oldPass", "newStrongPassword"
	account := &domain.Account{ID: userID, PasswordHash: "hashedOldPass"}
	s.mockUserRepo.On("GetById", mock.Anything, userID).Return(account, nil).Once()
	s.mockPassSvc.On("ComparePassword", "hashedOldPass", oldPass).Return(nil).Once()
	s.mockPassSvc.On("HashPassword", newPass).Return("hashedNewPass", nil).Once()
	s.mockUserRepo.On("UpdatePassword", mock.Anything, userID, "hashedNewPass").Return(nil).Once()

	// Act
	err := s.usecase.UpdatePassword(s.ctx, userID, oldPass, newPass)

	// Assert
	s.NoError(err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestLoginWithSocial_Google_NewUser() {
	// Arrange
	code := "google-auth-code"
	googleToken := &oauth2.Token{AccessToken: "google-access-token"}
	userInfo := &domain.GoogleUserInfo{ID: "google-id", Email: "new@google.com", Name: "Google User"}
	refreshClaims := &domain.JWTClaims{RegisteredClaims: jwt.RegisteredClaims{ID: "jti-1", ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}}

	s.mockGoogleSvc.On("ExchangeCodeForToken", mock.Anything, code).Return(googleToken, nil).Once()
	s.mockGoogleSvc.On("GetUserInfo", mock.Anything, googleToken).Return(userInfo, nil).Once()
	s.mockUserRepo.On("GetByEmail", mock.Anything, userInfo.Email).Return(nil, domain.ErrNotFound).Once()
	s.mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.Account")).Return(nil).Once()
	s.mockJWTSvc.On("GenerateAccessToken", mock.Anything, domain.RoleUser).Return("access-token", &domain.JWTClaims{}, nil).Once()
	s.mockJWTSvc.On("GenerateRefreshToken", mock.Anything).Return("refresh-token", refreshClaims, nil).Once()
	s.mockTokenRepo.On("CreateToken", mock.Anything, mock.AnythingOfType("*domain.Token")).Return(&domain.Token{}, nil).Once()

	// Act
	account, _, _, err := s.usecase.LoginWithSocial(s.ctx, domain.AuthProviderGoogle, code)

	// Assert
	s.NoError(err)
	s.Equal(userInfo.Email, account.Email)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockGoogleSvc.AssertExpectations(s.T())
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestLogout_Success() {
	// Arrange
	userID := "user-to-logout"
	s.mockTokenRepo.On("DeleteToken", mock.Anything, string(domain.RefreshToken), userID).Return(nil).Once()

	// Act
	err := s.usecase.Logout(s.ctx, userID)

	// Assert
	s.NoError(err)
	s.mockTokenRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestUpdateProfile_Success() {
	// Arrange
	account := &domain.Account{
		ID:    "user-1",
		Email: "new@example.com",
		UserDetail: &domain.UserDetail{
			Username: "newUsername",
		},
	}
	s.mockUserRepo.On("ExistsByEmail", mock.Anything, account.Email, account.ID).Return(false, nil).Once()
	s.mockUserRepo.On("ExistsByUsername", mock.Anything, account.UserDetail.Username, account.ID).Return(false, nil).Once()
	s.mockUserRepo.On("UpdateProfile", mock.Anything, *account).Return(nil).Once()

	// Act
	updatedAccount, err := s.usecase.UpdateProfile(s.ctx, account)

	// Assert
	s.NoError(err)
	s.Equal(account, updatedAccount)
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestUpdateProfile_EmailExists() {
	// Arrange
	account := &domain.Account{ID: "user-1", Email: "existing@example.com", UserDetail: &domain.UserDetail{}}
	s.mockUserRepo.On("ExistsByEmail", mock.Anything, account.Email, account.ID).Return(true, nil).Once()

	// Act
	_, err := s.usecase.UpdateProfile(s.ctx, account)

	// Assert
	s.ErrorIs(err, domain.ErrEmailExists)
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestForgetPassword_Success() {
	// Arrange
	email := "test@example.com"
	user := &domain.Account{ID: "user-1", Email: email, UserDetail: &domain.UserDetail{Username: "tester"}}
	utilityClaims := &domain.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "token-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	s.mockUserRepo.On("GetByEmail", mock.Anything, email).Return(user, nil).Once()
	s.mockJWTSvc.On("GenerateUtilityToken", user.ID).Return("utility-token", utilityClaims, nil).Once()
	s.mockTokenRepo.On("CreateToken", mock.Anything, mock.AnythingOfType("*domain.Token")).Return(&domain.Token{}, nil).Once()

	// --- CONCURRENCY HANDLING ---
	s.mockEmailSvc.Wg.Add(1)
	s.mockEmailSvc.On("SendPasswordResetEmail", user.Email, user.UserDetail.Username, "utility-token").Return(nil).Once()

	// Act
	err := s.usecase.ForgetPassword(s.ctx, email)
	s.mockEmailSvc.Wg.Wait() // Block until email goroutine is done

	// Assert
	s.NoError(err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
	s.mockEmailSvc.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestResetPassword_Success() {
	// Arrange
	resetToken := "valid-reset-token"
	newPassword := "newStrongPassword123"
	claims := &domain.JWTClaims{UserID: "user-1", RegisteredClaims: jwt.RegisteredClaims{ID: "jti-1"}}

	s.mockJWTSvc.On("ValidateToken", resetToken).Return(claims, nil).Once()
	s.mockTokenRepo.On("GetToken", mock.Anything, string(domain.ResetPasswordToken), "jti-1").Return("jti-1", nil).Once()
	s.mockPassSvc.On("HashPassword", newPassword).Return("hashedNewPassword", nil).Once()
	s.mockUserRepo.On("UpdateUserFields", mock.Anything, "user-1", mock.Anything).Return(nil).Once()
	s.mockTokenRepo.On("DeleteToken", mock.Anything, string(domain.ResetPasswordToken), "jti-1").Return(nil).Once()

	// Act
	err := s.usecase.ResetPassword(s.ctx, resetToken, newPassword)

	// Assert
	s.NoError(err)
	s.mockJWTSvc.AssertExpectations(s.T())
	s.mockTokenRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertExpectations(s.T())
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestRegisterOrg_Success() {
	// Arrange
	name, email, orgType := "New Org", "org@example.com", "gov"
	s.mockUserRepo.On("GetByEmail", mock.Anything, email).Return(nil, domain.ErrNotFound).Once()
	s.mockPassSvc.On("HashPassword", "defaultPassword123").Return("hashedDefault", nil).Once()
	s.mockUserRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.Account")).Return(nil).Once()

	// Act
	err := s.usecase.RegisterOrg(s.ctx, name, email, orgType)

	// Assert
	s.NoError(err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockPassSvc.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestGetOrgs_Success() {
	// Arrange
	filter := domain.GetOrgsFilter{Page: 1, PageSize: 10}
	expectedOrgs := []*domain.Account{{ID: "org-1"}}
	var expectedTotal int64 = 1
	s.mockUserRepo.On("GetOrgs", mock.Anything, filter).Return(expectedOrgs, expectedTotal, nil).Once()

	// Act
	orgs, total, err := s.usecase.GetOrgs(s.ctx, filter)

	// Assert
	s.NoError(err)
	s.Equal(expectedOrgs, orgs)
	s.Equal(expectedTotal, total)
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestGetOrgById_Success() {
	// Arrange
	orgID := "org-123"
	expectedOrg := &domain.Account{ID: orgID}
	s.mockUserRepo.On("GetById", mock.Anything, orgID).Return(expectedOrg, nil).Once()

	// Act
	org, err := s.usecase.GetOrgById(s.ctx, orgID)

	// Assert
	s.NoError(err)
	s.Equal(expectedOrg, org)
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *UserUsecaseTestSuite) TestUpdateOrgFields_Success() {
	// Arrange
	orgID := "org-123"
	updateMap := map[string]interface{}{"name": "Updated Name"}
	s.mockUserRepo.On("UpdateUserFields", mock.Anything, orgID, updateMap).Return(nil).Once()

	// Act
	err := s.usecase.UpdateOrgFields(s.ctx, orgID, updateMap)

	// Assert
	s.NoError(err)
	s.mockUserRepo.AssertExpectations(s.T())
}
