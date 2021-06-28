Provider.tf ---->>   The provider file contains secret/access key's that allows terraform's communication
with aws using publically exposed API's.


webserver.tf ----> This file contains the code which will create the actual infrastructure.

The cidr_block for vpc is 10.31.0.0/21 which provides us with 2048 ip's which will suffice our needs
 at present and can also be scaled in future.


Terraform version used -- > Terraform v0.12.30

AWS provider version ---> provider.aws v3.37.0

2 public and 2 private subnets created to incorporte private ec2 instances in private subnet  and
publically accessible load balancers in public subnet.

2 subnets are created as application load balancers required two subnets in two different AZ's.

minimum ports are allowed in each security group which allows port 80 for http communication
and port 22 to access private instances.

An ASG is created with latest ami. The ami section is kept static so that the launch configuration
wont change by itself whenever new ami is available or a new instance is launched.

The configuration consists of two ebs volumes one for / i-e root block and the other one for
data/logs .

web server included in nginx.



The same template can be used to deploy the above mentioned infrastructure in any AWS account
just need to change the secret_key and access_key .

A bucket policy is implemented on s3 so that load balancer can access the bucket for logging.

The created s3 is encrypted using ss3-s3 at rest.

Monitoring template is set for web server's so we receive an alert every time scale in
scale out happens.

The load metric is set for cpu CPUUtilization.
As soon as cpu utilization hots the threshold an instance will spin up
as mentioned in the launch config.


For starters we have created a root volume and secondary volume of
100 gb each.
This can later be scaled as per the requirement.


TRAFFIC- FLOW
===================

Internet ---> external load balancer(FQDN) --> internal load balancer --> ec2 instance ---> nginx(web server) 
