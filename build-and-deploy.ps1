# Set namespace
$namespace = "jokenation"

Write-Host "Building image"

# Build images
./mvnw -f ./authservice spring-boot:build-image
./mvnw -f ./gateway spring-boot:build-image
./mvnw -f ./quoteservice spring-boot:build-image
./mvnw -f ./jokeservice spring-boot:build-image

Write-Host "Image created!"

# Load images into Docker Desktop Kubernetes (optional if using Docker Desktop)
Write-Host "Loading image to docker desktop)..."
docker tag authservice:0.0.1-SNAPSHOT authservice:latest
docker tag gateway:0.0.1-SNAPSHOT gateway:latest
docker tag quoteservice:0.0.1-SNAPSHOT quoteservice:latest
docker tag jokeservice:0.0.1-SNAPSHOT jokeservice:latest

# (Optional step if using another runtime: skip this on GitHub Actions etc.)

# Create namespace
kubectl get namespace $namespace -o name > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Created namespace '$namespace'..."
    kubectl create namespace $namespace
} else {
    Write-Host "Namespace '$namespace' already exists"
}

# Apply all YAMLs
Write-Host "Deploy to kubernetes"
kubectl apply -f ./k8s --namespace $namespace

Write-Host "`nDone '$namespace'."

Write-Host "`nTips:"
Write-Host "- Check status: kubectl get pods -n $namespace"
Write-Host "- Test API: curl http://jokenation.local/jokes/random"
