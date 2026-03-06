# Authentication Methods Guide

A comprehensive **8-article series** covering every major authentication method — from session cookies to blockchain wallets. Each article includes theoretical explanation (Turkish) + production-ready code (JavaScript).

## 📚 Article Series

| #   | Topic                             | Framework         | Article                                                                                                                | Code                             | Status |
| --- | --------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------ |
| 0   | Introduction to Authentication    | —                 | [Read](https://medium.com/@mem3t/kimlik-doğrulama-nedir-authentication-authorization-ve-session-yönetimi-a0aa964a5fe3) | —                                | ✅     |
| 1   | Session-Based Authentication      | Express + Fastify | [Read](https://medium.com/@mem3t/session-based-authentication-klasik-ama-güçlü-0e0e9b07815f)                           | [Code](apps/session-auth/)       | ✅     |
| 2   | JWT & Refresh Token               | Express + Fastify | [Read](https://medium.com/@mem3t/jwt-refresh-token-stateless-authenticationın-modern-yüzü-faae7d2b0450)                | [Code](apps/jwt-auth/)           | ✅     |
| 3   | OAuth 2.0 & Social Login          | Express + Fastify | [Read](https://medium.com/@mem3t/oauth-2-0-social-login-google-ile-giriş-yap-butonunun-arkasındaki-dünya-91000af00844) | [Code](apps/oauth-social-login/) | ✅     |
| 4   | Enterprise SSO (OIDC & SAML)      | Express + Fastify | [Read](https://medium.com/@mem3t/enterprise-sso-kurumsal-dünyanın-giriş-kapısı-oidc-saml-2-0-dfd49162f019)             | [Code](apps/enterprise-sso/)     | ✅     |
| 5   | Multi-Factor Authentication       | Express + Fastify | —                                                                                                                      | —                                | ⬜     |
| 6   | Passwordless (WebAuthn, Passkeys) | Express + Fastify | —                                                                                                                      | —                                | ⬜     |
| 7   | Blockchain & Web3 Auth            | Express + Fastify | —                                                                                                                      | —                                | ⬜     |
| 8   | API & Service-to-Service          | Express + Fastify | —                                                                                                                      | —                                | ⬜     |

## 🏗️ Repository Structure

```
auth-methods-guide/
├── apps/
│   ├── shared/                  # Shared utilities (logger, crypto, errors, validators etc.)
│   ├── jwt-auth/                # Article 2
│   ├── session-auth/            # Article 1
│   ├── oauth-social-login/      # Article 3 (coming soon)
│   ├── enterprise-sso/          # Article 4 (coming soon)
│   ├── mfa/                     # Article 5 (coming soon)
│   ├── passwordless/            # Article 6 (coming soon)
│   ├── web3-auth/               # Article 7 (coming soon)
│   ├── service-auth/            # Article 8 (coming soon)
│   └── ...
├── package.json                 # Workspace root
```

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 22
- **yarn** ≥ 4.0.0
- **Docker** + Docker Compose

### Install

```bash
git clone https://github.com/ExorTek/nodejs-auth-methods-guide.git
cd nodejs-auth-methods-guide
yarn install
```

### Run an Implementation

Each implementation has its own Docker setup for databases and a dev script:

```bash
# Example: JWT Auth with Express
docker compose up -d          # Start MongoDB
cd ../../
cp apps/jwt-auth/express/.env.example apps/jwt-auth/express/.env
pnpm jwt:express              # Start server on :3000
```

See each implementation's README for detailed instructions.

## 🎯 Design Principles

- **Security-first** — every vulnerability discussed with OWASP references
- **Production-ready** — not toy examples; error handling, logging, graceful shutdown
- **Bilingual** — Turkish articles for theory, English code + documentation
- **Framework comparison** — Express and Fastify side by side where applicable
- **No magic** — manual implementations before library abstractions

## 🔒 Security

All implementations follow these practices:

- Input validation on every endpoint
- Password hashing with Argon2 + optional pepper
- Secure HTTP headers via Helmet
- CORS configuration
- Request ID tracking
- Structured logging
- Environment-based secrets (never hard-coded)
- Graceful shutdown with connection cleanup

## 📝 Code Standards

- All code in English (variables, functions, comments)
- ESM (`import`/`export`) throughout
- `async`/`await` — no callbacks
- No `console.log` — use pino logger
- JSDoc comments on public functions
- Clean error handling via custom error classes

**⚠️ DISCLAIMER / UYARI**

> This repository is an **educational resource** created for an article series on authentication methods.
> The code is designed to **demonstrate concepts and patterns**, not to be used as-is in production.
> Do not copy-paste this code into your projects without a thorough security review specific to your use case.
>
> Bu repo, authentication yöntemlerini anlatan bir makale serisi için hazırlanmış **eğitim amaçlı** bir kaynaktır.
> Kodlar **kavram ve pattern gösterimi** için tasarlanmıştır, production'da olduğu gibi kullanılmak için değil.
> Kendi projenize uygulamadan önce güvenlik gereksinimlerinize özel bir inceleme yapmanız şiddetle tavsiye edilir.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
