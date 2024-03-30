# cprime
Task : Create AWS EKS Cluster and Node Groups using Terraform via AWS DevOps
Architecture:
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/ba64f249-5b0f-4b46-bf60-c1966cbce70d)

//
Configure Terraform backend:
 
Terraform Backends (make sure bucket is already there and use latest terraform version)
 
**Create DynamoDB Tables  for Terraform State Locking**
steps:
Table Name: iacdevops-dev-tfstate
Partition key (Primary Key): LockID (Type as String)
Table settings: Use default settings (checked)
Click on Create

terraform.tfvars which autoloads for all environment creations will have only generic variables.
**Create Secure Parameters in Parameter Store for AWS credentials**
sample:
'Go to Services -> Systems Manager -> Application Management -> Parameter Store -> Create Parameter
Name: /CodeBuild/MY_AWS_ACCESS_KEY_ID
Descritpion: My AWS Access Key ID for Terraform CodePipeline Project
Tier: Standard
Type: Secure String
Rest all defaults
Value: <value of access key >
create buildspec.yml(for plan) and appspec.yml (for apply) = where we are going to use terraform comments for EKS deployments
//

👍AWS Codepipline:

1. Create code commit
   ![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/a7b4eba4-db36-4a86-b8dd-2fb27df49ff4)

2. create code build
   ![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/e0f6014e-22e2-42dd-b9f0-0e87ab07b51a)

3. create codepipeline
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/0a05ccb3-0854-4dec-8dbe-cc3074e752f6)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/28465c9f-6813-4549-bd3e-060d2ceed953)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/9396d2c4-3417-48fb-bc4d-a5179de40b80)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/8a24e6b4-a401-4c91-bacf-b5278edce65e)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/b7fa4493-a96b-43b2-a501-32b6f6a0cebe)



steps:

Go to Services -> CodePipeline -> Create Pipeline
Pipeline settings
Pipeline Name: <pipeline name>
Service role: New Service Role
rest all defaults
Artifact store: Default Location
Encryption Key: Default AWS Managed Key
Click Next >
Source Stage
Source Provider: codecommit
Repository name: repo name
Branch name: main
Change detection options: leave to defaults as checked
Output artifact format: leave to defaults as CodePipeline default
Add Build Stage
Build Provider: AWS CodeBuild
Region: N.Virginia
Project Name: Click on Create Project
Project Name: project name
Description: cprime_test
Environment image: Managed Image
Operating System: Amazon Linux 2
Runtimes: Standard
Image: latest available today (aws/codebuild/amazonlinux2-x86_64-standard:5.0)
Environment Type: Linux
Service Role: New (leave to defaults including Role Name)
Build specifications: use a buildspec file
Buildspec name - optional: buildspec.yml (Ensure that this file is present in root folder of your codecommit repository)
Rest all leave to defaults
Click on Continue to CodePipeline
Project Name: This value should be auto-populated
Build Type: Single Build
Review Stage
Click on Create Pipeline

4.Create IAM Policy with Systems Manager Get Parameter Read Permission and attached to codepipeline roles.

//
👍Terraform Configs Folder: **check terraform-manifests folder for all codes**
c1-versions.tf
c2-01-generic-variables.tf
c2-02-local-values.tf
c3-01-vpc-variables.tf
c3-02-vpc-module.tf
c3-03-vpc-outputs.tf
c4-01-ec2bastion-variables.tf
c4-02-ec2bastion-outputs.tf
c4-03-ec2bastion-securitygroups.tf
c4-04-ami-datasource.tf
c4-05-ec2bastion-instance.tf
c4-06-ec2bastion-elasticip.tf
c4-07-ec2bastion-provisioners.tf
//
👍variable part
c5-01-eks-variables.tf
# EKS Cluster Input Variables
variable "cluster_name" {
  description = "Name of the EKS cluster. Also used as a prefix in names of related resources."
  type        = string
  default     = "eksdemo"
}

variable "cluster_service_ipv4_cidr" {
  description = "service ipv4 cidr for the kubernetes cluster"
  type        = string
  default     = null
}

variable "cluster_version" {
  description = "Kubernetes minor version to use for the EKS cluster (for example 1.21)"
  type = string
  default     = null
}
variable "cluster_endpoint_private_access" {
  description = "Indicates whether or not the Amazon EKS private API server endpoint is enabled."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access" {
  description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled. When it's set to `false` ensure to have a proper private access with `cluster_endpoint_private_access = true`."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# EKS Node Group Variables
 c5-03-iamrole-for-eks-cluster.tf
# Create IAM Role
resource "aws_iam_role" "eks_master_role" {
  name = "${local.name}-eks-master-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

# Associate IAM Policy to IAM Role
resource "aws_iam_role_policy_attachment" "eks-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_master_role.name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_master_role.name
}
Step-04: c5-04-iamrole-for-eks-nodegroup.tf
# IAM Role for EKS Node Group 
resource "aws_iam_role" "eks_nodegroup_role" {
  name = "${local.name}-eks-nodegroup-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodegroup_role.name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodegroup_role.name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodegroup_role.name
}
# c5-05-securitygroups-eks.tf
# Security Group for EKS Node Group
c5-06-eks-cluster.tf
# Create AWS EKS Cluster
resource "aws_eks_cluster" "eks_cluster" {
  name     = "${local.name}-${var.cluster_name}"
  role_arn = aws_iam_role.eks_master_role.arn
  version = var.cluster_version

  vpc_config {
    subnet_ids = module.vpc.public_subnets
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs    
  }

  kubernetes_network_config {
    service_ipv4_cidr = var.cluster_service_ipv4_cidr
  }
  
  # Enable EKS Cluster Control Plane Logging
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.eks-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks-AmazonEKSVPCResourceController,
  ]
}

eks-node-group-public.tf
# Create AWS EKS Node Group - Public
resource "aws_eks_node_group" "eks_ng_public" {
  cluster_name    = aws_eks_cluster.eks_cluster.name

  node_group_name = "${local.name}-eks-ng-public"
  node_role_arn   = aws_iam_role.eks_nodegroup_role.arn
  subnet_ids      = module.vpc.public_subnets
  #version = var.cluster_version #(Optional: Defaults to EKS Cluster Kubernetes version)    
  
  ami_type = "AL2_x86_64"  
  capacity_type = "ON_DEMAND"
  disk_size = 20
  instance_types = ["t3.medium"]
  
  
  remote_access {
    ec2_ssh_key = "eks-terraform-key"
  }

  scaling_config {
    desired_size = 1
    min_size     = 1    
    max_size     = 2
  }

  # Desired max percentage of unavailable worker nodes during node group update.
  update_config {
    max_unavailable = 1    
    #max_unavailable_percentage = 50    # baesd on need ANY ONE TO USE
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.eks-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eks-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eks-AmazonEC2ContainerRegistryReadOnly,
  ] 

  tags = {
    Name = "Public-Node-Group"
  }
}

eks-node-group-private.tf
# Create AWS EKS Node Group - Private
resource "aws_eks_node_group" "eks_ng_private" {
  cluster_name    = aws_eks_cluster.eks_cluster.name

  node_group_name = "${local.name}-eks-ng-private"
  node_role_arn   = aws_iam_role.eks_nodegroup_role.arn
  subnet_ids      = module.vpc.private_subnets
  #version = var.cluster_version #(Optional: Defaults to EKS Cluster Kubernetes version)    
  
  ami_type = "AL2_x86_64"  
  capacity_type = "ON_DEMAND"
  disk_size = 20
  instance_types = ["t3.medium"]
  
  
  remote_access {
    ec2_ssh_key = "eks-terraform-key"    
  }

  scaling_config {
    desired_size = 1
    min_size     = 1    
    max_size     = 2
  }

  # Desired max percentage of unavailable worker nodes during node group update.
  update_config {
    max_unavailable = 1    
    #max_unavailable_percentage = 50    # ANY ONE TO USE
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.eks-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eks-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eks-AmazonEC2ContainerRegistryReadOnly,
  ]  
  tags = {
    Name = "Private-Node-Group"
  }
}

#eks.auto.tfvars
cluster_name = "eksdemo1"
cluster_service_ipv4_cidr = "172.20.0.0/16"
cluster_version = "1.26"
cluster_endpoint_private_access = true
cluster_endpoint_public_access = true
cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]

c5-02-eks-outputs.tf
# EKS Cluster Outputs
output "cluster_id" {
  description = "The name/id of the EKS cluster."
  value       = aws_eks_cluster.eks_cluster.id
}

output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster."
  value       = aws_eks_cluster.eks_cluster.arn
}

output "cluster_certificate_authority_data" {
  description = "Nested attribute containing certificate-authority-data for your cluster. This is the base64 encoded certificate data required to communicate with your cluster."
  value       = aws_eks_cluster.eks_cluster.certificate_authority[0].data
}

output "cluster_endpoint" {
  description = "The endpoint for your EKS Kubernetes API."
  value       = aws_eks_cluster.eks_cluster.endpoint
}

output "cluster_version" {
  description = "The Kubernetes server version for the EKS cluster."
  value       = aws_eks_cluster.eks_cluster.version
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster. On 1.14 or later, this is the 'Additional security groups' in the EKS console."
  value       = [aws_eks_cluster.eks_cluster.vpc_config[0].security_group_ids]
}

output "cluster_iam_role_name" {
  description = "IAM role name of the EKS cluster."
  value       = aws_iam_role.eks_master_role.name 
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN of the EKS cluster."
  value       = aws_iam_role.eks_master_role.arn
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

output "cluster_primary_security_group_id" {
  description = "The cluster primary security group ID created by the EKS cluster on 1.14 or later. Referred to as 'Cluster security group' in the EKS console."
  value       = aws_eks_cluster.eks_cluster.vpc_config[0].cluster_security_group_id
}

# EKS Node Group Outputs - Public
output "node_group_public_id" {
  description = "Public Node Group ID"
  value       = aws_eks_node_group.eks_ng_public.id
}

output "node_group_public_arn" {
  description = "Public Node Group ARN"
  value       = aws_eks_node_group.eks_ng_public.arn
}

output "node_group_public_status" {
  description = "Public Node Group status"
  value       = aws_eks_node_group.eks_ng_public.status 
}

output "node_group_public_version" {
  description = "Public Node Group Kubernetes Version"
  value       = aws_eks_node_group.eks_ng_public.version
}

# EKS Node Group Outputs - Private

output "node_group_private_id" {
  description = "Node Group 1 ID"
  value       = aws_eks_node_group.eks_ng_private.id
}

output "node_group_private_arn" {
  description = "Private Node Group ARN"
  value       = aws_eks_node_group.eks_ng_private.arn
}

output "node_group_private_status" {
  description = "Private Node Group status"
  value       = aws_eks_node_group.eks_ng_private.status 
}

output "node_group_private_version" {
  description = "Private Node Group Kubernetes Version"
  value       = aws_eks_node_group.eks_ng_private.version
}


✌️Run the Aws DevOps pipeline then  check the plan and apply  (create drift pipeline to check plans daily)

👌 **Verify the following Services using AWS Management Console**
Go to Services -> Elastic Kubernetes Service -> Clusters
Verify the following
Overview
Workloads
Configuration
Details
Compute
Networking
Add-Ons
Authentication
Logging
Update history
Tags
Step-13: Install kubectl CLI
Install kubectl CLI
Step-14: Configure kubeconfig for kubectl

# Install Kubectl on bastion host and Configure kubeconfig for kubectl
https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html

update config:
aws eks --region <region-code> update-kubeconfig --name <cluster_name>
aws eks --region us-east-1 update-kubeconfig --name hr-dev-eksdemo1

# List Worker Nodes
kubectl get nodes
kubectl get nodes -o wide
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/8fb8fb19-0a82-4d1d-b58c-180e27c2f56d)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/ad7a7d3b-bc81-4745-93e0-49113ebd60a3)


# Verify Services
kubectl get svc


Connect to EKS Worker Nodes using Bastion Host
# Connect to Bastion EC2 Instance
ssh -i private-key/eks-terraform-key.pem ec2-user@<Bastion-EC2-Instance-Public-IP>
cd /tmp

# Connect to Kubernetes Worker Nodes - Public Node Group
ssh -i private-key/eks-terraform-key.pem ec2-user@<Public-NodeGroup-EC2Instance-PublicIP> 
[or]
ec2-user@<Public-NodeGroup-EC2Instance-PrivateIP>

# Connect to Kubernetes Worker Nodes - Private Node Group from Bastion Host
ssh -i eks-terraform-key.pem ec2-user@<Private-NodeGroup-EC2Instance-PrivateIP>
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/f45f5bed-6fba-4daa-889f-a45ad7595bcb)

##### REPEAT BELOW STEPS ON BOTH PUBLIC AND PRIVATE NODE GROUPS ####
# Verify if kubelet and kube-proxy running
ps -ef | grep kube

# Verify kubelet-config.json
cat /etc/kubernetes/kubelet/kubelet-config.json

# Verify kubelet kubeconfig
cat /var/lib/kubelet/kubeconfig
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/34da17e5-8186-487a-acef-05b5a6d27f24)

# Verify clusters.cluster.server value(EKS Cluster API Server Endpoint)   with wget 
Try with wget on Node Group EC2 Instances (both public and private)
wget <Kubernetes API Server Endpoint>
wget https://0cbda14fd801e669f05c2444fb16d1b5.gr7.us-east-1.eks.amazonaws.com
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/0d0e7dbe-dbb4-4f65-85a4-468637497f01)

--------------------------------------------------------------------------


**Verify Namespaces and Resources in Namespaces**
# Verify Namespaces
kubectl get namespaces
kubectl get ns 
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/e83b725c-b5d9-4f92-91f6-86cb9507aaaa)


# Verify Resources in kube-node-lease namespace
kubectl get all -n kube-node-lease

# Verify Resources in kube-public namespace
kubectl get all -n kube-public

# Verify Resources in default namespace
kubectl get all -n default
Observation: 
1. Kubernetes Service: Cluster IP Service for Kubernetes Endpoint

# Verify Resources in kube-system namespace
kubectl get all -n kube-system
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/b5d5776c-4d28-4408-a123-153bafecd4b5)

# Verify System pods 
kubectl get pods
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/421f58da-7e67-4032-b3c6-cbc905f3a64b)

# Verify Daemon Sets in kube-system namespace
kubectl get ds -n kube-system
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/32cc2dae-eb7d-4980-82f2-1f0679b05eec)

# Describe aws-node Daemon Set
kubectl describe ds aws-node -n kube-system 

# Describe kube-proxy Daemon Set
kubectl describe ds kube-proxy -n kube-system

**Sample nginx deployment**
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/287f5170-22c4-42de-a574-d7d6eca06d23)
![image](https://github.com/Muralidharan-lab/cprime/assets/63875844/54e22072-b0f6-4229-8fd2-245bbbe833e1)
