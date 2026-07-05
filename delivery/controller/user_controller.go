package controller

import (
	"EthioGuide/domain"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type UserController struct {
	userUsecase      domain.IUserUsecase
	procedureUsecase domain.ISearchUseCase
	checklistUsecase domain.IChecklistUsecase
	refreshTokenTTL  int
}

func NewUserController(uc domain.IUserUsecase, puc domain.ISearchUseCase, cl domain.IChecklistUsecase, refreshTokenTTL time.Duration) *UserController {
	return &UserController{
		userUsecase:      uc,
		procedureUsecase: puc,
		checklistUsecase: cl,
		refreshTokenTTL:  int(refreshTokenTTL.Seconds()),
	}
}

func isMobileClient(c *gin.Context) bool {
	return c.GetHeader("X-Client-Type") == "mobile"
}

// @Summary      Refresh Access Token
// @Description  Refresh Access Token for web and mobile
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Success      200 {string}  "New Access Token"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /auth/refresh [post]
func (ctrl *UserController) HandleRefreshToken(c *gin.Context) {
	if isMobileClient(c) {
		// --- Mobile Client Logic ---
		refreshToken, err := extractBearerToken(c)
		if err != nil {
			HandleError(c, err)
			return
		}

		newAccess, newRefresh, err := ctrl.userUsecase.RefreshTokenForMobile(c.Request.Context(), refreshToken)
		if err != nil {
			HandleError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
		})

	} else {
		// --- Web Client Logic ---
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil {
			HandleError(c, domain.ErrAuthenticationFailed)
			return
		}

		newAccess, err := ctrl.userUsecase.RefreshTokenForWeb(c.Request.Context(), refreshToken)
		if err != nil {
			HandleError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"access_token": newAccess})
	}
}

// @Summary      Register a new user
// @Description  Creates a new user account with the provided details.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body RegisterRequest true "User Registration Details"
// @Success      201 {object} UserResponse "User created Successfully"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /auth/register [post]
func (ctrl *UserController) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	userDetail := &domain.UserDetail{
		Username:         req.Username,
		SubscriptionPlan: domain.SubscriptionNone,
		IsBanned:         false,
		IsVerified:       true,
	}
	account := &domain.Account{
		Name:          req.Name,
		Email:         req.Email,
		PasswordHash:  req.Password,
		ProfilePicURL: "https://res.cloudinary.com/dmcsjc9yv/image/upload/v1757316658/placeholder_jereof.jpg",
		Role:          domain.RoleUser,
		UserDetail:    userDetail,
	}

	err := ctrl.userUsecase.Register(c.Request.Context(), account)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully", "user": ToUserResponse(account)})
}

// @Summary      Login a new user
// @Description  Login a user account with the provided details.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "User Registration Details"
// @Success      201 {object} LoginResponse  "Login Successful"
// @Failure      400 {string}  "invalid
// @Failure      500 {string}  "invalid
// @Router       /auth/login [post]
func (ctrl *UserController) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	account, accessToken, refreshToken, err := ctrl.userUsecase.Login(c.Request.Context(), req.Identifier, req.Password)
	if err != nil {
		HandleError(c, err)
		return
	}

	if isMobileClient(c) {
		c.JSON(http.StatusOK, &LoginResponse{
			User:         ToUserResponse(account),
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	} else {
		setAuthCookie(c, refreshToken, ctrl.refreshTokenTTL)
		c.JSON(http.StatusOK, &LoginResponse{
			User:        ToUserResponse(account),
			AccessToken: accessToken,
		})
	}
}

// @Summary      Get Profile
// @Description  Get user's profile detail.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Success      200 {object} UserResponse "Profile Retrieved"
// @Failure      400 {string}  "Invalid request"
// @Failure      404 {string}  "Invalid request"
// @Failure      500 {string}  "Server error"
// @Router       /auth/me [get]
func (ctrl *UserController) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	account, err := ctrl.userUsecase.GetProfile(c.Request.Context(), userID.(string))
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, ToUserResponse(account))
}

// @Summary      Update password
// @Description  Update user's password.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        request body ChangePasswordRequest true "Password Change Detail"
// @Success      200 {string}  "Password changed"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /auth/me/password [patch]
func (ctrl *UserController) UpdatePassword(c *gin.Context) {
	accountID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	err := ctrl.userUsecase.UpdatePassword(c.Request.Context(), accountID.(string), req.OldPassword, req.NewPassword)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// @Summary      Social Login
// @Description  Login with third party auth.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body SocialLoginRequest true "Social Login Detail."
// @Success      200 {object} LoginResponse "Login successful"
// @Failure      400 {string}  "Invalid request"
// @Failure      500 {string}  "Server error"
// @Router       /auth/social [post]
func (ctrl *UserController) SocialLogin(c *gin.Context) {
	var req SocialLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	code, err := url.QueryUnescape(req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to URL-decode the pasted code: " + err.Error()})
		return
	}

	account, accessToken, refreshToken, err := ctrl.userUsecase.LoginWithSocial(c.Request.Context(), req.Provider, code)
	if err != nil {
		HandleError(c, err)
		return
	}

	if isMobileClient(c) {
		c.JSON(http.StatusOK, &LoginResponse{
			User:         ToUserResponse(account),
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	} else {
		setAuthCookie(c, refreshToken, ctrl.refreshTokenTTL)
		c.JSON(http.StatusOK, &LoginResponse{
			User:        ToUserResponse(account),
			AccessToken: accessToken,
		})
	}
}

// @Summary      Update Profile
// @Description  Update user's profile.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        request body UserUpdateRequest true "Updated Account Details"
// @Success      200 {object} domain.Account "Account Updated"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /auth/me/ [patch]
func (ctrl *UserController) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	var req UserUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// 1. Fetch current account from usecase
	account, err := ctrl.userUsecase.GetProfile(c.Request.Context(), userID.(string))
	if err != nil {
		HandleError(c, err)
		return
	}

	// 2. Convert DTO → domain.Account with updates applied
	updatedAccount := ToDomainAccountUpdate(&req, account)

	// 3. Call usecase with pure domain model
	savedAccount, err := ctrl.userUsecase.UpdateProfile(c.Request.Context(), updatedAccount)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, ToUserResponse(savedAccount))
}

// @Summary      Logout
// @Description  Logout a user.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Success      200 {string}  "Log out successful"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /auth/logout/ [post]
func (ctrl *UserController) Logout(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}
	if isMobileClient(c) {
		err := ctrl.userUsecase.Logout(c.Request.Context(), userID.(string))
		if err != nil {
			HandleError(c, err)
			return
		}
	} else {
		unsetAuthCookie(c)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// @Summary      Forgot Password
// @Description  Forgot password.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body ForgotDTO true "User Email"
// @Success      200 {string}  "Reset token sent"
// @Failure      400 {string}  "Invalid request"
// @Failure      500 {string}  "Server error"
// @Router       /auth/forgot [post]
func (ctrl *UserController) HandleForgot(c *gin.Context) {
	var req ForgotDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	err := ctrl.userUsecase.ForgetPassword(c.Request.Context(), req.Email)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Reset token sent"})
}

// @Summary      Reset Password
// @Description  Reset password.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body ResetDTO true "Reset Token and New Password"
// @Success      200 {string}  "Reset token sent"
// @Failure      400 {string}  "Invalid request"
// @Failure      500 {string}  "Server error"
// @Router       /auth/reset [post]
func (ctrl *UserController) HandleReset(c *gin.Context) {
	var req ResetDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	err := ctrl.userUsecase.ResetPassword(c.Request.Context(), req.ResetToken, req.NewPassword)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password Updated Successfully"})
}

// @Summary      Verify Account
// @Description  Verify User Account.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body ActivateDTO true "Reset Token and New Password"
// @Success      200 {string}  "Reset token sent"
// @Failure      400 {string}  "Invalid request"
// @Failure      500 {string}  "Server error"
// @Router       /auth/verify [post]
func (ctrl *UserController) HandleVerify(c *gin.Context) {
	var req ActivateDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if err := ctrl.userUsecase.VerifyAccount(c.Request.Context(), req.ActivateToken); err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User Activated Successfully"})
}

// @Summary      Create an Organization Account
// @Description  Creates a new organization account with the provided details. Must be an admin.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        request body OrgCreateRequest true "Organization details"
// @Success      201 {string}  "Organization created Successfully"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /orgs [post]
func (ctrl *UserController) HandleCreateOrg(c *gin.Context) {
	var req OrgCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	err := ctrl.userUsecase.RegisterOrg(c.Request.Context(), req.Name, req.Email, req.OrgType)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Organization created Successfully"})
}

// @Summary      Get List of Organizations
// @Description  Get list of organizations.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        page              query     int     false  "Page number (default 1)"
// @Param        pageSize          query     int     false  "Results per page (default 10)"
// @Param        type              query     string  false  "Filter by organization ID"
// @Param        q                 query     string  false  "Sort by field (e.g. createdAt, fee, processingTime)"
// @Success      201 {object} OrgsListPaginated "Organization created Successfully"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /orgs [get]
func (ctrl *UserController) HandleGetOrgs(c *gin.Context) {
	var filter domain.GetOrgsFilter
	filter.Type = c.Query("type")
	filter.Query = c.Query("q")

	page, _ := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	pageSize, _ := strconv.ParseInt(c.DefaultQuery("pageSize", "1"), 10, 64)

	filter.Page = page
	filter.PageSize = pageSize

	accounts, total, err := ctrl.userUsecase.GetOrgs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "could not get organizations"})
		return
	}
	orgsResponse := make([]OrganizationResponseDTO, len(accounts))
	for i, acc := range accounts {
		orgsResponse[i] = ToOrganizationDTO(acc)
	}

	// pagination := &PaginatedOrgsResponse{
	// 	Total:    total,
	// 	Page:     page,
	// 	PageSize: pageSize,
	// }

	c.JSON(http.StatusOK, gin.H{"data": toOrgsListPaginated(orgsResponse, total, page, pageSize)})
}

// @Summary      Get an Organization Account
// @Description  Get an organization's details.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        id path string true "Organization Account ID"
// @Success      201 {object} OrganizationResponseDTO "Organization created Successfully"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /orgs/{id} [get]
func (ctrl *UserController) HandleGetOrgById(c *gin.Context) {
	orgId := c.Param("id")
	account, err := ctrl.userUsecase.GetOrgById(c.Request.Context(), orgId)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": ToOrganizationDTO(account)})
}

// @Summary      Update an Organization Account Detail
// @Description  Update an organization's details. Must be an owner of the account.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        id path string true "Organization Account ID"
// @Param        request body UpdateOrgRequest true "Updated Details of Organization."
// @Success      201 {string}  "organization updated successfully"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /orgs/{id} [patch]
func (ctrl *UserController) HandleUpdateOrgs(c *gin.Context) {
	orgId := c.Param("id")
	var req UpdateOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	update := make(map[string]interface{})

	if req.Name != nil {
		update["name"] = *req.Name
	}
	if req.ProfilePicURL != nil {
		update["profile_pic_url"] = *req.ProfilePicURL
	}
	if req.Description != nil {
		update["organization_detail.description"] = *req.Description
	}
	if req.Location != nil {
		update["organization_detail.location"] = *req.Location
	}
	if req.PhoneNumbers != nil {
		update["organization_detail.phone_numbers"] = req.PhoneNumbers
	}
	if req.ContactInfo != nil {
		if req.ContactInfo.Website != nil {
			update["organization_detail.contact_info.website"] = *req.ContactInfo.Website
		}
		if req.ContactInfo.Socials != nil {
			update["organization_detail.contact_info.socials"] = req.ContactInfo.Socials
		}
	}

	if len(update) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	err := ctrl.userUsecase.UpdateOrgFields(c.Request.Context(), orgId, update)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "organization updated successfully"})
}

// @Summary      Search
// @Description  Application wide search.
// @Tags         Search
// @Accept       json
// @Produce      json
// @Param        q                 query     string  false  "Search term"
// @Param        page              query     int     false  "Page number (default 1)"
// @Param        limit             query     int     false  "Results per page (default 10)"
// @Success      200 {object} SearchResultResponse "Search Results"
// @Failure      400 {string}  "invalid
// @Failure      409 {string}  "invalid"
// @Failure      500 {string}  "invalid"
// @Router       /search [get]
func (ctrl *UserController) HandleSearch(c *gin.Context) {
	query := c.Query("q")
	page, err := strconv.ParseInt(c.Query("page"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	limit, errlimit := strconv.ParseInt(c.Query("limit"), 10, 64)
	if errlimit != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	result := &domain.SearchFilterRequest{
		Query: query,
		Page:  page,
		Limit: limit,
	}

	searchResult, err := ctrl.procedureUsecase.Search(c.Request.Context(), *result)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to search"})
		return
	}

	c.JSON(http.StatusOK, ToSearchJSON(searchResult))
}

// @Summary      Create Checklist
// @Description  Create new checklist.
// @Tags         Checklist
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        request body CreateChecklistRequest true "Procedure ID"
// @Success      200 {object} UserProcedureResponse "Checklist added"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /checklists [post]
func (ctrl *UserController) HandleCreateChecklist(c *gin.Context) {
	var req CreateChecklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	user_id, err := c.Get("userID")
	if !err {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are logged out, try to log in again"})
		return
	}

	userProcedure, errCreate := ctrl.checklistUsecase.CreateChecklist(c.Request.Context(), user_id.(string), req.ProcedureID)
	if errCreate != nil {
		HandleError(c, errCreate)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": ToControllerUserProcedure(userProcedure)})
}

// @Summary      Get User's Procedures
// @Description  Get User's ongoing procedures list
// @Tags         Checklist
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Success      200 {array} UserProcedureResponse "Checklist added"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /checklists/myProcedures [get]
func (ctrl *UserController) HandleGetProcedures(c *gin.Context) {
	user_id, err := c.Get("userID")
	if !err {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are logged out, try to log in again"})
		return
	}

	userProcedures, errGet := ctrl.checklistUsecase.GetProcedures(c.Request.Context(), user_id.(string))
	if errGet != nil {
		HandleError(c, errGet)
		return
	}

	ProcdeureResponses := make([]*UserProcedureResponse, len(userProcedures))
	for i, prod := range userProcedures {
		ProcdeureResponses[i] = ToControllerUserProcedure(prod)
	}

	c.JSON(http.StatusOK, gin.H{"message": ProcdeureResponses})
}

// @Summary      Get User's Ongoing Procedures by ID
// @Description  Get Checklist by ID
// @Tags         Checklist
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        userProcedureId path string true "UserProcedureId"
// @Success      200 {array} ChecklistResponse "Checklist added"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /checklists/{userProcedureId} [get]
func (ctrl *UserController) HandleGetChecklistById(c *gin.Context) {
	userProcedureId := c.Param("userProcedureId")

	checklists, err := ctrl.checklistUsecase.GetChecklistByUserProcedureID(c.Request.Context(), userProcedureId)
	if err != nil {
		HandleError(c, err)
		return
	}

	checklistResponses := make([]*ChecklistResponse, len(checklists))
	for i, check := range checklists {
		checklistResponses[i] = ToControllerChecklist(check)
	}

	c.JSON(http.StatusOK, gin.H{"message": checklistResponses})
}

// @Summary      Update Checklist by ID
// @Description  Update Checklist by ID
// @Tags         Checklist
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Bearer token"
// @Param        checklistID path string true "the id of the checklist to be marked done or undone"
// @Success      200 {array} UserProcedureResponse "Checklist added"
// @Failure      400 {string}  "Invalid request"
// @Failure      401 {string}  "Unauthorized"
// @Failure      500 {string}  "Server error"
// @Router       /checklists/{checklistID} [patch]
func (ctrl *UserController) HandleUpdateChecklist(c *gin.Context) {
	ChecklistID := c.Param("checklistID")

	checklist, err := ctrl.checklistUsecase.UpdateChecklist(c.Request.Context(), ChecklistID)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": ToControllerChecklist(checklist)})
}

// --- HELPER FUNCTIONS ---

// extractBearerToken is a helper to get the token from the Authorization header.
func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", domain.ErrAuthenticationFailed
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", domain.ErrAuthenticationFailed
	}

	return strings.TrimPrefix(authHeader, prefix), nil
}

func setAuthCookie(c *gin.Context, refreshToken string, refreshTokenTTL int) {
	if refreshToken != "" {
		c.SetCookie("refresh_token", refreshToken, refreshTokenTTL, "/", "", false, true)
	}
}

func unsetAuthCookie(c *gin.Context) {
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
}
