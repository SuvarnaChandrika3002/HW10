## Docker Hub Image
Reflection on Development & Deployment Process
1. Setting Up the Project

During this assignment, I worked on building a complete FastAPI application with a SQLAlchemy-based user model, password hashing, authentication, and token generation. One of the initial challenges was structuring the project folder properly and ensuring that the app, database models, schemas, and tests all worked together without circular imports.

2. Database & ORM Challenges

A major challenge was configuring SQLAlchemy with Postgres both locally and inside CI/CD. I had to troubleshoot issues such as missing drivers (psycopg2-binary), engine configuration errors, and database session handling during integration tests. Making sure that tests could run against an isolated test database was an important learning point.

3. Password Hashing & Security

Implementing hashing safely using bcrypt and Passlib was another key part. The bcrypt 72-byte limit required special handling. I implemented truncation logic and wrapped the hashing methods to avoid edge-case failures. Understanding how to balance security with practical constraints was a valuable experience.

4. Writing & Fixing Tests

The tests initially failed due to missing dependencies (httpx, Playwright) and incomplete model logic. Debugging integration tests helped reveal logic issues (e.g., last_login not updating). These failures guided improvements in database commits, refresh behavior, and model methods.

5. CI/CD Pipeline Setup

Setting up GitHub Actions for automated testing, security checks, and deployment was one of the more challenging parts. The pipeline required:

Creating a Postgres service inside CI

Installing dependencies correctly

Installing Playwright browsers

Ensuring fast and reproducible builds using caching

Fixing path/venv differences between Windows and Linux

It took several iterations to resolve errors, but it provided a deep understanding of how real-world CI environments operate.

6. Docker & Deployment

Building and pushing Docker images to Docker Hub was another key milestone. The CI/CD pipeline builds images on every push to main and pushes both latest and SHA-tagged versions. This made the deployment reproducible and automated.

7. Key Takeaways

Debugging CI is very different from debugging locally.

Tests help catch real logic issues you might otherwise miss.

Security concerns like safe password hashing require careful attention.

Automation is powerful—once CI/CD works, everything becomes smoother.

Clear project structure and documentation makes development easier.

This FastAPI application has been containerized using Docker and published to Docker Hub.

You can pull the image using the command:

```bash
docker pull sc673/module10_is601:latest
