package router

import (
	"EthioGuide/delivery/controller"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	_ "EthioGuide/docs"

	"github.com/gin-contrib/cors"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRouter initializes the Gin router and registers all application routes.
func SetupRouter(
	userController *controller.UserController,
	procedureController *controller.ProcedureController,
	catagorieController *controller.CategoryController,
	geminiController *controller.GeminiController,
	feedbackController *controller.FeedbackController,
	postController *controller.PostController,
	noticeController *controller.NoticeController,
	PreferencesController *controller.PreferencesController,
	aiChatController *controller.AIChatController,
	authMiddleware gin.HandlerFunc,
	translationMiddleware gin.HandlerFunc,
	proOnlyMiddleware gin.HandlerFunc,
	requireAdminRole gin.HandlerFunc,
	requireAdminOrOrgRole gin.HandlerFunc,
) *gin.Engine {

	router := gin.Default()

	config := cors.Config{
		AllowOrigins: []string{
			"http://localhost:3000",
			"https://ethio-guide.vercel.app",
			"https://your-production-site.com",
			"https://ethio-guide-frontend-b3et.vercel.app"
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Client-Type", "lang"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(config))
	router.Use(translationMiddleware)

	// Health check endpoint - always public
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Group all routes under a versioned prefix
	v1 := router.Group("/api/v1")
	{
		v1.GET("/search", userController.HandleSearch)

		// --- Public Routes ---
		// These endpoints do not require any authentication.
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/register", userController.Register)
			authGroup.POST("/login", userController.Login)
			authGroup.POST("/refresh", userController.HandleRefreshToken)
			authGroup.POST("/social", userController.SocialLogin)
			authGroup.POST("/verify", userController.HandleVerify)
			authGroup.POST("/forgot", userController.HandleForgot)
			authGroup.POST("/reset", userController.HandleReset)
		}

		// --- Private Routes (Require Authentication) ---
		// All routes in this group are protected by the base AuthMiddleware.
		apiGroup := v1.Group("/")
		apiGroup.Use(authMiddleware)
		{
			// --- Standard User Routes ---
			// Any logged-in user (regardless of role or subscription) can access these.
			aiGroup := apiGroup.Group("/ai")
			aiGroup.Use(authMiddleware)
			{
				aiGroup.POST("/translate", geminiController.Translate)
				aiGroup.POST("/guide", aiChatController.AIChatController)
				aiGroup.GET("/history", aiChatController.AIChatHistoryController)
			}

			// --- PRO Subscription Routes ---
			// These routes require the user to be logged in AND have a "pro" subscription.
			// We chain the ProOnlyMiddleware after the main auth middleware.
			proGroup := apiGroup.Group("/pro")
			proGroup.Use(proOnlyMiddleware)
			{
				// Example: A more advanced AI feature only for paying users.
				// You would need to create this controller method.
				// proGroup.POST("/ai/summarize", geminiController.SummarizeContent)
			}

			// --- Admin Routes ---
			// These routes require the user to be logged in AND have the "Admin" role.
			adminGroup := apiGroup.Group("/admin")
			adminGroup.Use(requireAdminRole)
			{
				// Example: An endpoint for an admin to get a list of all users.
				// You would need to create this controller method.
				// adminGroup.GET("/users", userController.GetAllUsers)
			}

			// --- User Profile Routes ---
			// Any logged in user can access these routes to manage their profile
			authGroup := apiGroup.Group("/auth")
			authGroup.Use(authMiddleware)
			{
				authGroup.POST("/logout", userController.Logout)
				authGroup.GET("/me", userController.GetProfile)
				authGroup.PATCH("/me/password", userController.UpdatePassword)
				authGroup.PATCH("/me", userController.UpdateProfile)
				authGroup.GET("/me/preferences", PreferencesController.GetUserPreferences)
				authGroup.PATCH("/me/preferences", PreferencesController.UpdateUserPreferences)
			}

			checklists := v1.Group("/checklists")
			checklists.Use(authMiddleware)
			{
				checklists.POST("", userController.HandleCreateChecklist)
				checklists.GET("/:userProcedureId", userController.HandleGetChecklistById)
				checklists.PATCH("/:checklistID", userController.HandleUpdateChecklist)
				checklists.GET("/myProcedures", userController.HandleGetProcedures)
			}

			orgs := v1.Group("/orgs")
			{
				orgs.POST("", authMiddleware, requireAdminRole, userController.HandleCreateOrg)
				orgs.GET("", userController.HandleGetOrgs)
				orgs.GET("/:id", userController.HandleGetOrgById)
				orgs.PATCH("/:id", authMiddleware, requireAdminOrOrgRole, userController.HandleUpdateOrgs)
			}

			procedures := v1.Group("/procedures")
			{
				procedures.GET("", procedureController.SearchAndFilter)
				procedures.POST("", authMiddleware, requireAdminOrOrgRole, procedureController.CreateProcedure)
				procedures.GET("/:id", procedureController.GetProcedureByID)
				procedures.PATCH("/:id", authMiddleware, requireAdminOrOrgRole, procedureController.UpdateProcedure)
				procedures.DELETE("/:id", authMiddleware, requireAdminOrOrgRole, procedureController.DeleteProcedure)
				procedures.POST("/:id/feedback", authMiddleware, feedbackController.SubmitFeedback)
				procedures.GET("/:id/feedback", feedbackController.GetAllFeedbacksForProcedure)
			}

			feedback := v1.Group("/feedback")
			{
				feedback.GET("", authMiddleware, requireAdminOrOrgRole, feedbackController.GetAllFeedbacks)
				feedback.PATCH("/:id", authMiddleware, requireAdminOrOrgRole, feedbackController.UpdateFeedbackStatus)
			}

			discussions := v1.Group("/discussions")
			{
				discussions.POST("", authMiddleware, postController.CreatePost)
				discussions.GET("", postController.GetPosts)
				discussions.GET("/:id", postController.GetPostByID)
				discussions.PATCH("/:id", authMiddleware, postController.UpdatePost)
				discussions.DELETE("/:id", authMiddleware, requireAdminOrOrgRole, postController.DeletePost)
			}

			notices := v1.Group("/notices")
			{
				notices.POST("", authMiddleware, requireAdminOrOrgRole, noticeController.CreateNotice)
				notices.GET("", noticeController.GetNoticesByFilter)
				notices.PATCH("/:id", authMiddleware, requireAdminOrOrgRole, noticeController.UpdateNotice)
				notices.DELETE("/:id", authMiddleware, requireAdminOrOrgRole, noticeController.DeleteNotice)
			}

			categories := v1.Group("/categories")
			{
				categories.POST("", authMiddleware, requireAdminOrOrgRole, catagorieController.CreateCategory)
				categories.GET("", catagorieController.GetCategory)
			}

		}
	}

	// MOCK ROUTES
	{
		// 2) Users & Profiles
		users := v1.Group("/users")
		{
			users.GET("/:id", handleGetUser)
			users.GET("/me/summary", handleGetUserSummary)
		}

		// 3) Organizations
		orgs := v1.Group("/orgs")
		{
			orgs.GET("/pending", handleGetPendingOrgs)
			orgs.PATCH("/:id/approve", handleApproveOrg)
			orgs.GET("/:id/feedback", handleGetOrgFeedback)
		}

		// 4) Categories & Taxonomy
		categories := v1.Group("/categories")
		{
			categories.PATCH("/:id", handleUpdateCategory)
		}

		// 5) Procedures (core)
		procedures := v1.Group("/procedures")
		{
			procedures.PATCH("/:id/verify", handleVerifyProcedure)
			procedures.GET("/:id/audit", handleGetProcedureAudit)
			procedures.GET("/popular", handleGetPopularProcedures)
			procedures.GET("/recent", handleGetRecentProcedures)
		}

		// 8) Documents & File Vault
		v1.POST("/uploads/signature", handleUploadSignature)
		documents := v1.Group("/documents")
		{
			documents.POST("", handleCreateDocument)
			documents.GET("", handleGetDocuments)
			documents.GET("/:id", handleGetDocument)
			documents.PATCH("/:id", handleUpdateDocument)
			documents.DELETE("/:id", handleDeleteDocument)
		}

		// 9) Reminders & Notifications
		reminders := v1.Group("/reminders")
		{
			reminders.POST("", handleCreateReminder)
			reminders.GET("", handleGetReminders)
			reminders.PATCH("/:id", handleUpdateReminder)
			reminders.DELETE("/:id", handleDeleteReminder)
		}
		notifications := v1.Group("/notifications")
		{
			notifications.GET("", handleGetNotifications)
			notifications.PATCH("/:id/read", handleMarkNotificationRead)
		}

		// 10) Discussions (Community)
		discussions := v1.Group("/discussions")
		{
			discussions.POST("/:id/upvote", handleUpvoteDiscussion)
			discussions.POST("/:id/downvote", handleDownvoteDiscussion)
			discussions.POST("/:id/report", handleReportDiscussion)
		}

		// 11) Feedback (standalone updates)
		feedback := v1.Group("/feedback")
		{
			feedback.POST("/:id/upvote", handleUpvoteFeedback)
		}

		// 12) Official Notices
		notices := v1.Group("/notices")
		{
			notices.GET("/:id", handleGetNotice)
		}

		// 13) AI Guidance (Gemini)
		ai := v1.Group("/ai")
		{
			ai.POST("/mark-not-verified", handleAIMarkNotVerified)
			ai.POST("/speech-to-text", handleAISpeechToText)
		}

		// 14) Direct Messages
		dm := v1.Group("/dm/threads")
		{
			dm.POST("", handleCreateDMThread)
			dm.GET("", handleGetDMThreads)
			dm.GET("/:id", handleGetDMThread)
			dm.POST("/:id/messages", handleCreateDMMessage)
			dm.PATCH("/:id/close", handleCloseDMThread)
		}

		// 15) Subscriptions & Payments
		v1.GET("/plans", handleGetPlans)
		subscriptions := v1.Group("/subscriptions")
		{
			subscriptions.POST("", handleCreateSubscription)
			subscriptions.GET("/me", handleGetMySubscription)
			subscriptions.DELETE("/me", handleDeleteMySubscription)
		}
		v1.POST("/payments/webhook", handlePaymentsWebhook)

		// 16) Admin & Moderation
		admin := v1.Group("/admin")
		{
			admin.GET("/overview", handleAdminOverview)
			admin.GET("/flags", handleAdminGetFlags)
			admin.PATCH("/flags/:id/resolve", handleAdminResolveFlag)
			admin.GET("/auditlogs", handleAdminGetAuditLogs)
			admin.GET("/health", handleAdminHealth)
		}

		// 17) Notifications (server-side events)
		realtime := v1.Group("/realtime")
		{
			realtime.GET("/stream", handleRealtimeStream)
		}

		// 18) Localization
		i18n := v1.Group("/i18n")
		{
			i18n.GET("/locales", handleI18nGetLocales)
			i18n.GET("/strings", handleI18nGetStrings)
		}

		// 19) Analytics
		analytics := v1.Group("/analytics")
		{
			analytics.POST("/events", handleAnalyticsEvents)
		}
	}

	return router
}

// 2) Users & Profiles
func handleGetUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":     c.Param("id"),
		"name":   "Public User Name",
		"orgId":  "org_789",
		"badges": []string{"Top Contributor", "Verified"},
	})
}

func handleGetUserSummary(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"proceduresTracked": 5,
		"documents":         12,
		"remindersActive":   3,
	})
}

// 3) Organizations
func handleGetPendingOrgs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":   "org_pending_1",
				"name": "Pending Org A",
			},
		},
		"page":    1,
		"limit":   20,
		"total":   1,
		"hasNext": false,
	})
}

func handleApproveOrg(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":       c.Param("id"),
		"approved": true,
	})
}

func handleGetOrgFeedback(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":   "fb_1",
				"body": "This was very helpful!",
			},
		},
		"page":    1,
		"limit":   20,
		"total":   1,
		"hasNext": false,
	})
}

// 4) Categories & Taxonomy

func handleUpdateCategory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "name": "Updated Category Name"})
}

// 5) Procedures (core)

// func handleGetProcedures(c *gin.Context) {
// 	c.JSON(http.StatusOK, gin.H{
// 		"data": []gin.H{{
// 			"id":      "prc_123",
// 			"orgId":   "org_456",
// 			"title":   "Passport Renewal",
// 			"slug":    "passport-renewal",
// 			"summary": "Renew your Ethiopian passport in 5 steps.",
// 			"requirements": []gin.H{
// 				{"text": "2 passport photos"},
// 				{"text": "Old passport"},
// 			},
// 			"steps": []gin.H{
// 				{"order": 1, "text": "Book appointment"},
// 				{"order": 2, "text": "Submit documents"},
// 			},
// 			"fees": []gin.H{
// 				{"label": "Processing", "amount": 500, "currency": "ETB"},
// 			},
// 			"processingTime": gin.H{"minDays": 7, "maxDays": 14},
// 			"offices": []gin.H{
// 				{"city": "Addis Ababa", "address": "...", "hours": "Mon–Fri"},
// 			},
// 			"documentsRequired": []gin.H{
// 				{"name": "Application Form", "templateUrl": nil},
// 			},
// 			"tags":             []string{"passport", "id"},
// 			"languageVersions": gin.H{"enId": "prc_123", "amId": "prc_789"},
// 			"verified":         true,
// 			"updatedAt":        "2025-08-20T12:00:00Z",
// 		}},
// 		"page":    1,
// 		"limit":   20,
// 		"total":   1,
// 		"hasNext": false,
// 	})
// }

func handleVerifyProcedure(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "verified": true})
}

func handleGetProcedureAudit(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"user":      "admin_user",
				"change":    "Set verified to true",
			},
		},
	})
}

func handleGetPopularProcedures(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{{"id": "prc_123", "title": "Passport Renewal", "views": 1050}},
	})
}

func handleGetRecentProcedures(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{{"id": "prc_789", "title": "New Business License", "updatedAt": time.Now().UTC().Format(time.RFC3339)}},
	})
}

// 8) Documents & File Vault
func handleUploadSignature(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"signature": "cloudinary_signature_string",
		"timestamp": time.Now().Unix(),
		"apiKey":    "cloudinary_api_key",
		"cloudName": "your_cloud_name",
	})
}

func handleCreateDocument(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"id":      "doc_123",
		"userId":  "user_abc",
		"name":    "My Passport Scan",
		"fileUrl": "https://res.cloudinary.com/...",
		"type":    "passport",
	})
}

func handleGetDocuments(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":        "doc_123",
				"name":      "My Passport Scan",
				"fileUrl":   "https://res.cloudinary.com/...",
				"type":      "passport",
				"expiresOn": time.Now().AddDate(5, 0, 0).UTC().Format(time.RFC3339),
			},
		},
		"page":    1,
		"limit":   20,
		"total":   1,
		"hasNext": false,
	})
}

func handleGetDocument(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":        "doc_123",
		"userId":    "user_abc",
		"name":      "My Passport Scan",
		"fileUrl":   "https://res.cloudinary.com/...",
		"type":      "passport",
		"tags":      []string{"prc_123"},
		"issuedOn":  time.Now().AddDate(-5, 0, 0).UTC().Format(time.RFC3339),
		"expiresOn": time.Now().AddDate(5, 0, 0).UTC().Format(time.RFC3339),
		"ocrData":   gin.H{"name": "Test User"},
		"size":      1024,
	})
}

func handleUpdateDocument(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "name": "Updated Document Name"})
}

func handleDeleteDocument(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// 9) Reminders & Notifications
func handleCreateReminder(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"id": "rem_123", "title": "Renew Passport", "status": "ACTIVE"})
}

func handleGetReminders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":      "rem_123",
				"userId":  "user_abc",
				"title":   "Renew Passport",
				"dueAt":   time.Now().AddDate(0, 6, 0).UTC().Format(time.RFC3339),
				"channel": "email",
				"status":  "ACTIVE",
			},
		},
		"page":    1,
		"limit":   20,
		"total":   1,
		"hasNext": false,
	})
}

func handleUpdateReminder(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": "CANCELLED"})
}

func handleDeleteReminder(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func handleGetNotifications(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":   "notif_1",
				"body": "Your procedure 'Passport Renewal' has been updated.",
				"read": false,
			},
		},
		"page":    1,
		"limit":   20,
		"total":   1,
		"hasNext": false,
	})
}

func handleMarkNotificationRead(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// 10) Discussions (Community)
func handleUpvoteDiscussion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "votes": 13})
}

func handleDownvoteDiscussion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "votes": 11})
}

func handleReportDiscussion(c *gin.Context) {
	c.Status(http.StatusAccepted)
}

// Feedback
func handleUpvoteFeedback(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "votes": 6})
}

// 12) Official Notices
func handleGetNotice(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id":            "ntc_1",
		"orgId":         "org_456",
		"title":         "Holiday Office Closure",
		"body":          "All offices will be closed on...",
		"pinned":        true,
		"effectiveFrom": "2025-09-10T00:00:00Z",
		"createdAt":     "2025-08-15T10:00:00Z",
	})
}

// 13) AI Guidance}

func handleAIMarkNotVerified(c *gin.Context) {
	c.Status(http.StatusAccepted)
}

func handleAISpeechToText(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"text": "This is the recognized text from speech."})
}

// 14) Direct Messages
func handleCreateDMThread(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"id": "dm_thread_1", "status": "open"})
}

func handleGetDMThreads(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":            "dm_thread_1",
				"orgId":         "org_456",
				"status":        "open",
				"lastMessageAt": time.Now().UTC().Format(time.RFC3339),
			},
		},
	})
}

func handleGetDMThread(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"id": c.Param("id"),
		"messages": []gin.H{
			{
				"id":   "msg_1",
				"from": "user",
				"body": "Hello, I have a question.",
			},
		},
	})
}

func handleCreateDMMessage(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"id": "msg_new", "threadId": c.Param("id"), "body": "This is a new message."})
}

func handleCloseDMThread(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": "closed"})
}

// 15) Subscriptions & Payments
func handleGetPlans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":           "plan_pro",
				"name":         "Pro",
				"priceMonthly": 100,
				"currency":     "ETB",
				"features":     []string{"Direct Messages", "Auto-tick"},
			},
		},
	})
}

func handleCreateSubscription(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "pending", "clientSecret": "stripe_client_secret_string"})
}

func handleGetMySubscription(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"planId":     "plan_pro",
		"status":     "active",
		"currentEnd": time.Now().AddDate(0, 1, 0).UTC().Format(time.RFC3339),
	})
}

func handleDeleteMySubscription(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "cancelled", "message": "Subscription will be cancelled at the end of the current period."})
}

func handlePaymentsWebhook(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// 16) Admin & Moderation
func handleAdminOverview(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"uptime":        "99.99%",
		"dailyActives":  1500,
		"contentCounts": gin.H{"procedures": 120, "orgs": 30},
	})
}

func handleAdminGetFlags(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data": []gin.H{
			{
				"id":      "flag_1",
				"content": "Inappropriate discussion post.",
				"type":    "discussion",
				"status":  "pending",
			},
		},
	})
}

func handleAdminResolveFlag(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": "resolved"})
}

func handleAdminGetAuditLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": []gin.H{{"timestamp": time.Now(), "actor": "admin", "action": "deleted procedure prc_xyz"}}})
}

func handleAdminHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"services": gin.H{
			"database":   "connected",
			"cache":      "connected",
			"gemini_api": "ok",
		},
	})
}

// 17) Notifications (server-side events)
func handleRealtimeStream(c *gin.Context) {
	c.String(http.StatusOK, "This would be an SSE stream.")
}

// 18) Localization
func handleI18nGetLocales(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"supported": []string{"en", "am"}})
}

func handleI18nGetStrings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"welcomeMessage": "Welcome to EthioGuide",
		"search":         "Search",
	})
}

// 19) Analytics
func handleAnalyticsEvents(c *gin.Context) {
	c.Status(http.StatusAccepted)
}
