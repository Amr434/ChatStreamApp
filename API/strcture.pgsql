📂 ChatApp
│
├── 📂 Domain
│   ├── 📂 Entities
│   │   └── ApplicationUser.cs
│   ├── 📂 Enums
│   │   └── UserStatus.cs
│   └── 📂 Exceptions
│       └── DomainException.cs
│
├── 📂 Application
│   ├── 📂 Interfaces
│   │   ├── IUserRepository.cs         ← contracts for Infrastructure
│   │   └── IChatRepository.cs
│   ├── 📂 Services
│   │   └── IUserService.cs            ← contracts for use cases (called by API)
│   ├── 📂 Features
│   │   └── Users
│   │       ├── Commands
│   │       │   └── SetUserOfflineCommand.cs
│   │       └── Queries
│   │           └── GetUserByIdQuery.cs
│   └── 📂 Common
│       └── Exceptions
│           └── NotFoundException.cs
│
├── 📂 Infrastructure
│   ├── 📂 Persistence
│   │   └── ApplicationDbContext.cs
│   ├── 📂 Repositories
│   │   └── UserRepository.cs          ← implements IUserRepository
│   ├── 📂 Identity
│   │   └── ApplicationUserStore.cs
│   ├── 📂 Services
│   │   └── EmailService.cs            ← implements IEmailService
│   ├── 📂 Interfaces (optional)
│   │   └── internal EF/Identity contracts (rare)
│   └── InfrastructureServiceRegistration.cs
│
└── 📂 WebApi (or UI)
    ├── 📂 Controllers
    │   └── UserController.cs
    ├── Program.cs
    └── appsettings.json
