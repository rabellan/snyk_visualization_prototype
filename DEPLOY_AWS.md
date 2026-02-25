# Deploying the Snyk Dashboard to AWS

This guide covers pushing the containerized nginx static dashboard to AWS using **Elastic Container Registry (ECR)** and running it on **Elastic Container Service (ECS) with Fargate**.

---

## Prerequisites

- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) installed and configured (`aws configure`)
- [Docker](https://docs.docker.com/get-docker/) installed and running
- An AWS account with permissions for ECR and ECS

---

## Step 1: Build the Docker Image

From the project root (where the `Dockerfile` lives):

```bash
docker build -t snyk-dashboard .
```

Verify the image builds and runs locally:

```bash
docker run -p 8080:80 snyk-dashboard
# Open http://localhost:8080 to confirm the dashboard loads
```

---

## Step 2: Create an ECR Repository

```bash
aws ecr create-repository \
  --repository-name snyk-dashboard \
  --region us-east-1
```

Note the `repositoryUri` from the output — it will look like:

```
123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard
```

---

## Step 3: Authenticate Docker with ECR

```bash
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin \
    123456789012.dkr.ecr.us-east-1.amazonaws.com
```

Replace `123456789012` with your actual AWS account ID and adjust the region if needed.

---

## Step 4: Tag and Push the Image

```bash
# Tag the local image with the ECR URI
docker tag snyk-dashboard:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard:latest

# Push to ECR
docker push \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard:latest
```

---

## Step 5: Deploy to ECS (Fargate)

### 5a. Create an ECS Cluster

```bash
aws ecs create-cluster --cluster-name snyk-dashboard-cluster --region us-east-1
```

### 5b. Register a Task Definition

Create a file `task-definition.json`:

```json
{
  "family": "snyk-dashboard-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "snyk-dashboard",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard:latest",
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "essential": true
    }
  ]
}
```

Register it:

```bash
aws ecs register-task-definition \
  --cli-input-json file://task-definition.json \
  --region us-east-1
```

### 5c. Run the Service

You need a VPC with at least one public subnet and a security group that allows inbound TCP on port 80. Replace the placeholder IDs below with your own.

```bash
aws ecs create-service \
  --cluster snyk-dashboard-cluster \
  --service-name snyk-dashboard-service \
  --task-definition snyk-dashboard-task \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-XXXXXXXX],
    securityGroups=[sg-XXXXXXXX],
    assignPublicIp=ENABLED
  }" \
  --region us-east-1
```

---

## Step 6: Access the Running Container

Once the task reaches `RUNNING` status, find its public IP:

```bash
# Get the task ARN
aws ecs list-tasks \
  --cluster snyk-dashboard-cluster \
  --region us-east-1

# Describe the task to find the ENI
aws ecs describe-tasks \
  --cluster snyk-dashboard-cluster \
  --tasks <task-arn> \
  --region us-east-1

# Get the public IP from the ENI
aws ec2 describe-network-interfaces \
  --network-interface-ids <eni-id> \
  --query 'NetworkInterfaces[0].Association.PublicIp' \
  --output text \
  --region us-east-1
```

Open `http://<public-ip>` in your browser to view the dashboard.

---

## Updating the Deployment

When you make changes to the dashboard files, rebuild and push a new image, then force a new ECS deployment:

```bash
docker build -t snyk-dashboard .
docker tag snyk-dashboard:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard:latest
docker push \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/snyk-dashboard:latest

aws ecs update-service \
  --cluster snyk-dashboard-cluster \
  --service snyk-dashboard-service \
  --force-new-deployment \
  --region us-east-1
```

---

## Optional: Add a Load Balancer

For a stable public URL, create an **Application Load Balancer (ALB)** and attach it to the ECS service. This avoids relying on the ephemeral public IP of individual tasks. Use the `--load-balancers` flag when creating the service, pointing to your ALB target group.

---

## Cleanup

To avoid ongoing charges, delete resources when done:

```bash
aws ecs delete-service \
  --cluster snyk-dashboard-cluster \
  --service snyk-dashboard-service \
  --force \
  --region us-east-1

aws ecs delete-cluster \
  --cluster snyk-dashboard-cluster \
  --region us-east-1

aws ecr delete-repository \
  --repository-name snyk-dashboard \
  --force \
  --region us-east-1
```
