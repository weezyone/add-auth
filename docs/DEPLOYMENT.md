# Deployment Documentation

This document provides comprehensive deployment instructions for the authentication system across different environments and platforms.

**Before copying env names or npm scripts from the sections below**, confirm them against `src/config/index.ts`, `.env.example`, and `package.json`. Local truth: [DEVELOPMENT.md](./DEVELOPMENT.md). HTTP/CORS/CSRF: [API.md](./API.md). The default process is `src/index.ts` (`npm run dev` / `node dist/index.js` after `tsc`).

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Environment Setup](#environment-setup)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Database Deployment](#database-deployment)
- [Security Configuration](#security-configuration)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Optimization](#performance-optimization)
- [Troubleshooting](#troubleshooting)

## Deployment Overview

### Architecture Overview

The authentication system is designed for deployment in production environments with:

- **High Availability**: Multiple instances behind a load balancer
- **Scalability**: Horizontal scaling with stateless application servers
- **Security**: SSL/TLS termination, secure secrets management
- **Monitoring**: Application and infrastructure monitoring
- **Backup**: Automated database and configuration backups

### Deployment Strategies

1. **Blue-Green Deployment**: Zero-downtime deployments
2. **Rolling Updates**: Gradual replacement of instances
3. **Canary Releases**: Progressive rollout to subset of users
4. **Feature Flags**: Runtime feature toggling

## Environment Setup

### Production Environment Requirements

#### Infrastructure Requirements

- **CPU**: Minimum 2 vCPUs per instance
- **Memory**: Minimum 4GB RAM per instance
- **Storage**: 20GB+ SSD storage
- **Network**: 1Gbps+ network connectivity
- **Load Balancer**: Application Load Balancer with SSL termination

#### Software Requirements

- **Node.js**: Version 18.x LTS
- **PostgreSQL**: Version 14.x or higher
- **Redis**: Version 6.x or higher
- **Reverse Proxy**: Nginx or Apache
- **Process Manager**: PM2 or systemd

### Environment Variables

Create production environment configuration:

```bash
# Production .env file
NODE_ENV=production
PORT=3000
API_PREFIX=/api/v1

# Database Configuration
DATABASE_URL=postgresql://username:password@db-host:5432/auth_db
DB_HOST=db-host.example.com
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=secure_password_here
DB_SSL=true
DB_POOL_MIN=5
DB_POOL_MAX=20

# Redis Configuration
REDIS_URL=redis://redis-host:6379
REDIS_HOST=redis-host.example.com
REDIS_PORT=6379
REDIS_PASSWORD=secure_redis_password
REDIS_TLS=true

# JWT Configuration
JWT_SECRET=your-production-jwt-secret-64-characters-minimum
JWT_REFRESH_SECRET=your-production-refresh-secret-64-characters-minimum
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
JWT_ISSUER=your-app-name
JWT_AUDIENCE=your-app-audience

# RSA Keys
JWT_PRIVATE_KEY_PATH=/app/keys/private.key
JWT_PUBLIC_KEY_PATH=/app/keys/public.key

# Email Configuration
EMAIL_SERVICE=ses
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
EMAIL_FROM=noreply@yourdomain.com

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URL=https://yourdomain.com/auth/callback

# Security Configuration
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
SESSION_SECRET=your-session-secret-64-characters-minimum
CSRF_SECRET=your-csrf-secret-64-characters-minimum
CORS_ORIGIN=https://yourdomain.com

# SSL/TLS Configuration
SSL_KEY_PATH=/app/ssl/private.key
SSL_CERT_PATH=/app/ssl/certificate.crt
SSL_CA_PATH=/app/ssl/ca.crt

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE=/app/logs/app.log
LOG_MAX_SIZE=10m
LOG_MAX_FILES=10

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_PATH=/health
READY_CHECK_PATH=/ready
```

## Docker Deployment

### 1. Production Dockerfile

Create `Dockerfile`:

```dockerfile
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Create necessary directories
RUN mkdir -p logs keys ssl

# Set ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["node", "dist/index.js"]
```

### 2. Docker Compose for Production

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
    env_file:
      - .env.production
    volumes:
      - ./logs:/app/logs
      - ./keys:/app/keys:ro
      - ./ssl:/app/ssl:ro
    depends_on:
      - postgres
      - redis
    networks:
      - auth-network
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgres/init:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - auth-network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G

  redis:
    image: redis:6-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - auth-network
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - auth-network

networks:
  auth-network:
    driver: bridge

volumes:
  postgres_data:
  redis_data:

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### 3. Nginx Configuration

Create `nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream auth_backend {
        least_conn;
        server app:3000 max_fails=3 fail_timeout=30s;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        ssl_certificate /etc/nginx/ssl/certificate.crt;
        ssl_certificate_key /etc/nginx/ssl/private.key;

        # Rate limiting
        limit_req zone=auth burst=20 nodelay;

        # Proxy settings
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Health check
        location /health {
            proxy_pass http://auth_backend;
            access_log off;
        }

        # Auth endpoints with stricter rate limiting
        location /api/v1/auth/login {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://auth_backend;
        }

        location /api/v1/auth/register {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://auth_backend;
        }

        # General API endpoints
        location /api/ {
            proxy_pass http://auth_backend;
        }

        # Static files
        location /static/ {
            alias /var/www/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

### 4. Deploy with Docker Compose

```bash
# Build and deploy
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Scale application
docker-compose -f docker-compose.prod.yml up -d --scale app=3

# View logs
docker-compose -f docker-compose.prod.yml logs -f app

# Stop deployment
docker-compose -f docker-compose.prod.yml down
```

## Kubernetes Deployment

### 1. Kubernetes Manifests

Create `k8s/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-system
```

Create `k8s/secrets.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
  namespace: auth-system
type: Opaque
data:
  database-url: <base64-encoded-database-url>
  jwt-secret: <base64-encoded-jwt-secret>
  redis-password: <base64-encoded-redis-password>
```

Create `k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: auth-system
data:
  NODE_ENV: "production"
  PORT: "3000"
  API_PREFIX: "/api/v1"
  LOG_LEVEL: "info"
  BCRYPT_SALT_ROUNDS: "12"
  RATE_LIMIT_WINDOW: "15"
  RATE_LIMIT_MAX: "100"
```

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-api
  namespace: auth-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-api
  template:
    metadata:
      labels:
        app: auth-api
    spec:
      containers:
      - name: auth-api
        image: your-registry/auth-api:latest
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: redis-password
        envFrom:
        - configMapRef:
            name: auth-config
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: keys
          mountPath: /app/keys
          readOnly: true
      volumes:
      - name: keys
        secret:
          secretName: jwt-keys
```

Create `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-api-service
  namespace: auth-system
spec:
  selector:
    app: auth-api
  ports:
  - port: 80
    targetPort: 3000
  type: ClusterIP
```

Create `k8s/ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-api-ingress
  namespace: auth-system
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.yourdomain.com
    secretName: auth-api-tls
  rules:
  - host: api.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-api-service
            port:
              number: 80
```

### 2. Deploy to Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check deployment
kubectl get pods -n auth-system
kubectl get services -n auth-system
kubectl get ingress -n auth-system

# View logs
kubectl logs -f deployment/auth-api -n auth-system

# Scale deployment
kubectl scale deployment auth-api --replicas=5 -n auth-system
```

## Cloud Platform Deployment

### AWS Deployment

#### 1. ECS Deployment

Create `ecs-task-definition.json`:

```json
{
  "family": "auth-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "auth-api",
      "image": "your-account.dkr.ecr.region.amazonaws.com/auth-api:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:auth/database-url"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:auth/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-api",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/health || exit 1"],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

#### 2. RDS Configuration

```bash
# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier auth-db \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 14.6 \
  --master-username authuser \
  --master-user-password $DB_PASSWORD \
  --allocated-storage 100 \
  --storage-type gp2 \
  --storage-encrypted \
  --vpc-security-group-ids sg-12345678 \
  --db-subnet-group-name auth-subnet-group \
  --backup-retention-period 7 \
  --multi-az \
  --auto-minor-version-upgrade
```

#### 3. ElastiCache Configuration

```bash
# Create ElastiCache cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id auth-redis \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --engine-version 6.2 \
  --num-cache-nodes 1 \
  --security-group-ids sg-12345678 \
  --subnet-group-name auth-cache-subnet-group
```

### Google Cloud Platform

#### 1. Cloud Run Deployment

Create `cloudbuild.yaml`:

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/auth-api:$COMMIT_SHA', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/auth-api:$COMMIT_SHA']
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
      - 'run'
      - 'deploy'
      - 'auth-api'
      - '--image=gcr.io/$PROJECT_ID/auth-api:$COMMIT_SHA'
      - '--region=us-central1'
      - '--platform=managed'
      - '--allow-unauthenticated'
      - '--set-env-vars=NODE_ENV=production'
      - '--set-secrets=DATABASE_URL=database-url:latest'
      - '--set-secrets=JWT_SECRET=jwt-secret:latest'
```

#### 2. Deploy to Cloud Run

```bash
# Build and deploy
gcloud builds submit --config cloudbuild.yaml

# Update service
gcloud run services update auth-api \
  --region us-central1 \
  --set-env-vars NODE_ENV=production \
  --set-secrets DATABASE_URL=database-url:latest
```

### Azure Deployment

#### 1. Container Instances

Create `azure-container-instances.yaml`:

```yaml
apiVersion: '2019-12-01'
location: eastus
name: auth-api
properties:
  containers:
  - name: auth-api
    properties:
      image: your-registry.azurecr.io/auth-api:latest
      ports:
      - port: 3000
        protocol: TCP
      resources:
        requests:
          cpu: 2
          memoryInGB: 4
      environmentVariables:
      - name: NODE_ENV
        value: production
      - name: DATABASE_URL
        secureValue: postgresql://...
      - name: JWT_SECRET
        secureValue: your-jwt-secret
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - port: 3000
      protocol: TCP
tags:
  environment: production
  application: auth-api
```

## Database Deployment

### PostgreSQL Production Setup

#### 1. Database Configuration

Create `postgresql.conf` optimizations:

```conf
# Connection Settings
max_connections = 100
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 16MB
maintenance_work_mem = 512MB

# Write-Ahead Logging
wal_buffers = 16MB
checkpoint_completion_target = 0.9
checkpoint_timeout = 10min
max_wal_size = 2GB
min_wal_size = 1GB

# Query Planner
random_page_cost = 1.1
effective_io_concurrency = 200

# Security
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_ca_file = '/etc/ssl/certs/ca.crt'

# Logging
log_destination = 'csvlog'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
```

#### 2. Database Initialization

Create `init-db.sql`:

```sql
-- Create database
CREATE DATABASE auth_db;

-- Create user
CREATE USER auth_user WITH PASSWORD 'secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_user;

-- Connect to database
\c auth_db;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS audit;

-- Grant schema privileges
GRANT ALL ON SCHEMA auth TO auth_user;
GRANT ALL ON SCHEMA audit TO auth_user;
```

### Redis Production Setup

#### 1. Redis Configuration

Create `redis.conf`:

```conf
# Network
bind 127.0.0.1
protected-mode yes
port 6379

# Security
requirepass your_secure_redis_password
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG ""

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis/

# Append Only File
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
syslog-enabled yes
syslog-ident redis
```

## Security Configuration

### 1. SSL/TLS Setup

#### Generate SSL Certificates

```bash
# Generate private key
openssl genrsa -out private.key 2048

# Generate certificate signing request
openssl req -new -key private.key -out certificate.csr

# Generate self-signed certificate (for testing)
openssl x509 -req -days 365 -in certificate.csr -signkey private.key -out certificate.crt

# Or use Let's Encrypt
certbot certonly --standalone -d yourdomain.com
```

#### Configure SSL in Application

```typescript
import https from 'https';
import fs from 'fs';

const sslOptions = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH),
  ca: fs.readFileSync(process.env.SSL_CA_PATH),
  requestCert: false,
  rejectUnauthorized: false
};

const server = https.createServer(sslOptions, app);
```

### 2. Secrets Management

#### AWS Secrets Manager

```bash
# Create secret
aws secretsmanager create-secret \
  --name auth/database-url \
  --secret-string "postgresql://username:password@host:5432/database"

# Retrieve secret
aws secretsmanager get-secret-value \
  --secret-id auth/database-url \
  --query SecretString --output text
```

#### HashiCorp Vault

```bash
# Enable KV secrets engine
vault secrets enable -path=auth kv-v2

# Store secret
vault kv put auth/database url="postgresql://username:password@host:5432/database"

# Retrieve secret
vault kv get -field=url auth/database
```

## Monitoring and Logging

### 1. Application Monitoring

#### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'auth-api'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']
```

#### Grafana Dashboard

Create `dashboard.json`:

```json
{
  "dashboard": {
    "title": "Auth API Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors"
          }
        ]
      }
    ]
  }
}
```

### 2. Log Management

#### ELK Stack Configuration

Create `logstash.conf`:

```conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "auth-api" {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    mutate {
      add_field => { "service" => "auth-api" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "auth-api-%{+YYYY.MM.dd}"
  }
}
```

#### Filebeat Configuration

Create `filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /app/logs/*.log
  fields:
    service: auth-api
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

output.logstash:
  hosts: ["logstash:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

## Backup and Recovery

### 1. Database Backup

#### Automated PostgreSQL Backup

Create `backup-db.sh`:

```bash
#!/bin/bash

# Configuration
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="auth_db"
DB_USER="auth_user"
BACKUP_DIR="/backups"
RETENTION_DAYS=7

# Create backup directory
mkdir -p $BACKUP_DIR

# Generate backup filename
BACKUP_FILE="$BACKUP_DIR/auth_db_$(date +%Y%m%d_%H%M%S).sql"

# Create backup
pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME \
  --verbose --clean --no-owner --no-privileges \
  --format=custom > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Remove old backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

# Upload to S3 (optional)
aws s3 cp $BACKUP_FILE.gz s3://your-backup-bucket/database/
```

#### Backup Cron Job

```bash
# Add to crontab
0 2 * * * /path/to/backup-db.sh
```

### 2. Application Backup

#### Configuration Backup

Create `backup-config.sh`:

```bash
#!/bin/bash

# Configuration backup
tar -czf /backups/config_$(date +%Y%m%d).tar.gz \
  /app/.env \
  /app/keys/ \
  /app/ssl/ \
  /app/config/

# Upload to S3
aws s3 cp /backups/config_$(date +%Y%m%d).tar.gz s3://your-backup-bucket/config/
```

### 3. Disaster Recovery

#### Recovery Procedure

Create `restore-db.sh`:

```bash
#!/bin/bash

# Variables
BACKUP_FILE=$1
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="auth_db"
DB_USER="auth_user"

# Stop application
docker-compose down

# Restore database
gunzip -c $BACKUP_FILE | pg_restore -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME --clean --verbose

# Start application
docker-compose up -d

# Verify restore
curl -f http://localhost:3000/health
```

## Performance Optimization

### 1. Database Optimization

#### Query Optimization

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_sessions_user_id ON sessions(user_id);
CREATE INDEX CONCURRENTLY idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX CONCURRENTLY idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX CONCURRENTLY idx_audit_log_timestamp ON audit_log(timestamp);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'user@example.com';
```

### 2. Application Optimization

#### Connection Pooling

```typescript
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  
  // Pool configuration
  min: 5,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  
  // SSL configuration
  ssl: {
    rejectUnauthorized: false,
    ca: fs.readFileSync(process.env.DB_SSL_CA_PATH),
    cert: fs.readFileSync(process.env.DB_SSL_CERT_PATH),
    key: fs.readFileSync(process.env.DB_SSL_KEY_PATH)
  }
});
```

### 3. Caching Strategy

#### Redis Caching

```typescript
export class CacheService {
  private redis: Redis;
  
  constructor(redis: Redis) {
    this.redis = redis;
  }
  
  async get(key: string): Promise<string | null> {
    return await this.redis.get(key);
  }
  
  async set(key: string, value: string, ttl: number = 3600): Promise<void> {
    await this.redis.setex(key, ttl, value);
  }
  
  async del(key: string): Promise<void> {
    await this.redis.del(key);
  }
  
  async getUserFromCache(userId: string): Promise<User | null> {
    const cached = await this.get(`user:${userId}`);
    return cached ? JSON.parse(cached) : null;
  }
  
  async setUserInCache(user: User): Promise<void> {
    await this.set(`user:${user.id}`, JSON.stringify(user), 1800); // 30 minutes
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues

```bash
# Check database connectivity
pg_isready -h localhost -p 5432

# Check database logs
tail -f /var/log/postgresql/postgresql-*.log

# Check connections
psql -U auth_user -d auth_db -c "SELECT * FROM pg_stat_activity;"
```

#### 2. Redis Connection Issues

```bash
# Check Redis connectivity
redis-cli ping

# Check Redis logs
tail -f /var/log/redis/redis-server.log

# Check Redis info
redis-cli info
```

#### 3. Application Issues

```bash
# Check application logs
docker logs auth-api

# Check resource usage
docker stats auth-api

# Check health endpoint
curl -f http://localhost:3000/health
```

### Performance Issues

#### 1. High CPU Usage

```bash
# Check CPU usage
top -p $(pidof node)

# Profile application
node --prof app.js
node --prof-process isolate-*.log > profiling.txt
```

#### 2. Memory Issues

```bash
# Check memory usage
ps aux | grep node

# Generate heap snapshot
kill -USR2 $(pidof node)
```

#### 3. Database Performance

```sql
-- Check slow queries
SELECT query, mean_time, calls
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

### Emergency Procedures

#### 1. Application Rollback

```bash
# Rollback to previous version
docker-compose down
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

#### 2. Database Recovery

```bash
# Stop application
docker-compose down

# Restore from backup
./restore-db.sh /backups/latest-backup.sql.gz

# Start application
docker-compose up -d
```

#### 3. Scale Up Resources

```bash
# Scale application instances
docker-compose up -d --scale app=5

# Or in Kubernetes
kubectl scale deployment auth-api --replicas=5
```

---

This deployment documentation provides comprehensive guidance for deploying the authentication system in production environments. Regular updates and testing ensure reliable and secure deployments.