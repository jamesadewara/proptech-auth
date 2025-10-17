# 🏢 PropTech Auth

**Authentication & Authorization Web Service**  
A robust authentication and authorization microservice powering the PropTech ecosystem — providing secure access for real estate owners, their staff, and their clients.

---

## 🚀 Overview

`proptech-auth` is a standalone authentication and authorization web service built for a multi-tenant real estate platform.  
It manages **user registration, verification, login, invites, roles, and secure access control** for different tenants (real estate companies).

This service integrates seamlessly with other PropTech microservices and follows clean, scalable architecture principles.

---

## 🧩 Features

- 🧑‍💼 **Multi-Tenant Authentication** — Each real estate owner (tenant) manages their own users independently.  
- 🔐 **JWT-Based Authorization** — Secure access control for API requests.  
- 📧 **Email Verification & Password Reset** — Custom HTML templates for all email workflows.  
- 📨 **Invite System** — Tenants can invite staff and agents using verified email links.  
- 🧱 **Role-Based Access Control (RBAC)** — Owner, Agent, Staff, and Client roles with scoped permissions.  
- 💾 **SQLite (Dev), PostgreSQL (Main)** — Simple and scalable database environments.  
- ☁️ **AWS S3 Storage** — For static and media file handling in production.  
- 🌐 **Render Deployment** — Staging environment hosted on [Render](https://render.com).  
- 🧭 **Postman Collection** — Explore all API endpoints with the link below.

📄 **API Docs (Postman):**  
[👉 View Collection](https://warped-resonance-723855.postman.co/workspace/Team-Workspace~6a6f45a7-06bf-4910-8372-14e2a1d7948f/collection/27579261-183e00aa-2aa8-466e-9716-a78a02a91286?action=share&creator=27579261&active-environment=27579261-c41e3bd6-f656-41a7-81f4-7e5c7b2851a2)

---

## ⚙️ Environments

| Environment | Purpose | Hosting | Database | Storage | Notes |
|--------------|----------|----------|-----------|-----------|--------|
| **Development (Local)** | For local testing and debugging | Localhost | SQLite3 | Local static/media | Run with `python manage.py runserver` |
| **Staging** | For pre-deployment testing | Render | SQLite3 / PostgreSQL (optional) | Local static/media | Auto-deploy from main branch |
| **Production (Main)** | Live environment | AWS EC2 | PostgreSQL | AWS S3 Bucket | Scalable and secured setup |

---

## 🏗️ Tech Stack

- **Backend Framework:** Django REST Framework (DRF)  
- **Auth:** JWT (SimpleJWT)  
- **Database:** SQLite3 (Dev), PostgreSQL (Prod)  
- **Storage:** Local (Dev), AWS S3 (Prod)  
- **Hosting:** Render (Staging), AWS EC2 (Main)  
- **Email:** Django templated HTML emails for verification and invites  

---

## 🧰 Local Development Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/proptech-auth.git
cd proptech-auth
````

### 2️⃣ Create & Activate Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # On Windows use venv\Scripts\activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Setup Environment Variables

Create a `.env` file in the project root:

```
SECRET_KEY=your_secret_key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
DATABASE_URL=sqlite:///db.sqlite3
```

### 5️⃣ Run Migrations

```bash
python manage.py migrate
```

### 6️⃣ Start the Server

```bash
python manage.py runserver
```

Access at **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)**

---

## ☁️ Deployment

### 🔹 Staging (Render)

* Deploy directly from your GitHub repository.
* Configure environment variables under Render’s "Environment" tab.
* Use Render’s free PostgreSQL instance or SQLite for quick testing.

### 🔹 Production (AWS EC2)

* Configure `nginx + gunicorn` for serving the Django app.
* Use `PostgreSQL` (via Amazon RDS or managed instance).
* Use AWS S3 for static and media files.
* Set environment variables via `.env` or system environment.

---

## 📬 Email Templates

Located under:

```
templates/account/email/
├── base.html
├── verify_email.html
├── invite_email.html
└── password_reset_email.html
```

---

## 🧪 API Testing

You can explore, test, and verify all endpoints using the Postman collection:
👉 [PropTech Auth API Documentation](https://warped-resonance-723855.postman.co/workspace/Team-Workspace~6a6f45a7-06bf-4910-8372-14e2a1d7948f/collection/27579261-183e00aa-2aa8-466e-9716-a78a02a91286?action=share&creator=27579261&active-environment=27579261-c41e3bd6-f656-41a7-81f4-7e5c7b2851a2)

---

## 🧑‍💻 Maintainer

**James Adewara**
Backend, Mobile, Web & AI Developer
Building scalable, robust, and secure applications.

---

## 🪪 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
