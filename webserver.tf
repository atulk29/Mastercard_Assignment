resource  "aws_vpc" "Mastercard_VPC" {
  cidr_block = "10.31.0.0/21"
  instance_tenancy = "default"


tags = {
  Name = "Mastercard_VPC"
      }
}

resource "aws_key_pair" "Key-Pair"{
  key_name = "prodserver"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD3F6tyPEFEzV0LX3X8BsXdMsQz1x2cEikKDEY0aIj41qgxMCP/iteneqXSIFZBp5vizPvaoIR3Um9xK7PGoW8giupGn+EPuxIA4cDM4vzOqOkiMPhz5XK0whEjkVzTo4+S0puvDZuwIsdiW9mxhJc7tgBNL0cYlWSYVkz4G/fslNfRPW5mYAM49f4fhtxPb5ok4Q2Lg9dPKVHO/Bgeu5woMc7RY0p1ej6D4CKFE6lymSDJpW0YHX/wqE9+cfEauh7xZcG0q9t2ta6F6fmX0agvpFyZo8aFbXeUBr7osSCJNgvavWbM/06niWrOvYX2xwWdhXmXSrbX8ZbabVohBK41 email@example.com"
}


resource "aws_internet_gateway" "mastercard_internet_gateway"{
  vpc_id = aws_vpc.Mastercard_VPC.id

  tags = {
    Name = "mastercard_internet_gateway"
  }
}


resource "aws_eip" "NAT_gateway_EIP"{
  vpc = true
}


resource "aws_nat_gateway" "mastercard_nat_gateway"{
  allocation_id = aws_eip.NAT_gateway_EIP.id
  subnet_id = aws_subnet.public_subnet.id

  tags = {
    Name = "mastercard_nat_gateway"
  }
}


resource "aws_subnet" "private_subnet" {
  vpc_id = aws_vpc.Mastercard_VPC.id
  cidr_block = "10.31.3.0/24"
  availability_zone = "ap-south-1a"
tags = {
  Name = "private_subnet"
    }
}


resource "aws_subnet" "private_subnet_02"{
  vpc_id = aws_vpc.Mastercard_VPC.id
  cidr_block = "10.31.4.0/24"
  availability_zone = "ap-south-1b"

  tags = {
    Name = "private_subnet_02"

  }
}

resource "aws_route_table" "private_route_table"{
  vpc_id = aws_vpc.Mastercard_VPC.id

  route{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.mastercard_nat_gateway.id
  }
}

resource "aws_route_table" "private_route_table_02"{
  vpc_id = aws_vpc.Mastercard_VPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.mastercard_nat_gateway.id

  }

}

resource "aws_subnet" "public_subnet" {
  vpc_id = aws_vpc.Mastercard_VPC.id
  cidr_block = "10.31.5.0/24"
  map_public_ip_on_launch = "true"
  availability_zone = "ap-south-1a"

tags = {
  Name = "public_subnet"
    }
}


resource "aws_subnet" "public_subnet_02"{
  vpc_id = aws_vpc.Mastercard_VPC.id
  cidr_block = "10.31.6.0/24"
  map_public_ip_on_launch = "true"
  availability_zone = "ap-south-1b"

tags = {
  Name = "public_subnet_02"

  }

}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.Mastercard_VPC.id

  route{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mastercard_internet_gateway.id
  }
}



resource "aws_route_table" "public_route_table_02" {
  vpc_id = aws_vpc.Mastercard_VPC.id

  route{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mastercard_internet_gateway.id
  }

}


resource "aws_route_table_association" "public_route_to_pub_subnet" {
  subnet_id = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "private_route_to_pvt_subnet"{
  subnet_id = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_route_table.id

}

resource "aws_route_table_association" "private_route_to_pvt_subnet_02"{
  subnet_id = aws_subnet.private_subnet_02.id
  route_table_id = aws_route_table.private_route_table_02.id

}

resource "aws_route_table_association" "public_route_to_pub_subnet_02"{
  subnet_id = aws_subnet.public_subnet_02.id
  route_table_id = aws_route_table.public_route_table_02.id

}

resource "aws_s3_bucket" "s3"{
  bucket = "access-logs-lb-bucket"
  server_side_encryption_configuration {
    rule{
      apply_server_side_encryption_by_default{
        sse_algorithm = "AES256"
      }
    }

  }

tags = {
  Name = "access-logs-bucket"
  Environment = "Production"
      }
}

resource "aws_s3_bucket_policy" "s3_bucket_policy"{
  bucket = aws_s3_bucket.s3.id

  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {
                  "AWS": "arn:aws:iam::718504428378:root"
              },
              "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::access-logs-lb-bucket/*"
          },
          {
              "Effect": "Allow",
              "Principal": {
                  "Service": "delivery.logs.amazonaws.com"
              },
              "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::access-logs-lb-bucket/*",
              "Condition": {
                  "StringEquals": {
                      "s3:x-amz-acl": "bucket-owner-full-control"
                  }
              }
          },
          {
              "Effect": "Allow",
              "Principal": {
                  "Service": "delivery.logs.amazonaws.com"
              },
              "Action": "s3:GetBucketAcl",
              "Resource": "arn:aws:s3:::access-logs-lb-bucket"
          }
      ]
  })

}


resource "aws_launch_configuration" "Mastercard_ASG_launch_config"{
  name_prefix = "Mastercard_ASG_launch_config-"
  image_id = "ami-011c99152163a87ae" #Amazon Linux 2 AMI
  instance_type = "t3.2xlarge"
  key_name = "prodserver"

  root_block_device {

  delete_on_termination = true
  encrypted = true
  volume_size = 100
  volume_type = "gp2"
  }

  ebs_block_device {
  device_name = "/dev/sda1"
  delete_on_termination = true
  encrypted = true
  volume_size = 100
  volume_type = "gp2"

}

  security_groups =  "${aws_security_group.web_server_Sg.*.id}"

  user_data = <<USER_DATA
    #!/bin/bash
    yum update
    yum -y install nginx
    echo "$(curl http://169.254.169.254/latest/meta-data/local-ipv4)" > /usr/share/nginx/html/index.html
    chkconfig nginx on
    service nginx start
      USER_DATA

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "web_server_Sg"{
  description = "Allow inbound traffic from ports 80 and 22"
  vpc_id = aws_vpc.Mastercard_VPC.id
  ingress{
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress{
    description = "ssh"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress{
    description = "output from webserver"
    from_port = 0
    to_port  = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }
}


resource "aws_security_group" "external_lb_security_group" {
  description = "Allow inbound traffic from internet"
  vpc_id = aws_vpc.Mastercard_VPC.id

  ingress{
    description = "allow only TLS from vpc"
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = [aws_vpc.Mastercard_VPC.cidr_block]
  }

  egress{
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
tags = {
  Name = "external_lb_security_group"
      }
}


resource "aws_security_group" "internal_load_balancer_sg" {
  description = "Allow HTTP traffic to instances through Elastic Load Balancer"
  vpc_id = aws_vpc.Mastercard_VPC.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Allow HTTP through ELB Security Group"
  }
}

resource "aws_lb" "external_lb" {
  name = "external-lb"

  internal = false
  load_balancer_type = "application"
  subnets = [aws_subnet.public_subnet.id,aws_subnet.public_subnet_02.id]
  security_groups = "${aws_security_group.external_lb_security_group.*.id}"

  enable_deletion_protection= true

  access_logs {
    bucket = aws_s3_bucket.s3.bucket
    prefix = "lb_logs"
    enabled = true
}
  tags = {
    Environment = "Production"
      }
}


resource "aws_lb" "internal_load_balancer"{
  name = "Internal-lb"
  internal = true

  security_groups = "${aws_security_group.internal_load_balancer_sg.*.id}"
  subnets = [aws_subnet.private_subnet.id,aws_subnet.private_subnet_02.id]

  enable_deletion_protection = true

}


resource "aws_lb_target_group" "mastercard-tg"{
  name = "mastercard-tg"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.Mastercard_VPC.id
  target_type = "instance"

  health_check{
    interval = 20
    path = "/index.html"
    port = 80
    healthy_threshold = 5
    unhealthy_threshold = 2
    timeout = 5
    protocol = "HTTP"
    matcher = "200"
    }

}


resource "aws_lb_listener" "internal_lb_listener"{
  load_balancer_arn = "${aws_lb.internal_load_balancer.arn}"
  port = 80
  protocol = "HTTP"

  default_action {
    target_group_arn = "${aws_lb_target_group.mastercard-tg.arn}"
    type = "forward"
  }
}


resource "aws_autoscaling_group" "Mastercard_Asg"{
  name = "${aws_launch_configuration.Mastercard_ASG_launch_config.name}-asg"

  min_size = 1
  desired_capacity = 2
  max_size = 4


  health_check_type = "ELB"
  load_balancers = [aws_lb.internal_load_balancer.id]
  launch_configuration = aws_launch_configuration.Mastercard_ASG_launch_config.name
  target_group_arns = ["${aws_lb_target_group.mastercard-tg.arn}"]

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]

  metrics_granularity = "1Minute"

  vpc_zone_identifier = [aws_subnet.private_subnet.id]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "web_server_up_policy" {
  name = "web-policy-up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.Mastercard_Asg.name

}


resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_up" {
  alarm_name = "web_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "60"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.Mastercard_Asg.name
   }
   alarm_description = "This metric monitor ec2 cpu utilization"
   alarm_actions = [aws_autoscaling_policy.web_server_up_policy.arn]
}

resource "aws_autoscaling_policy" "web_server_down_policy"{
  name = "web_server_down_policy"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.Mastercard_Asg.name
}



resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_down" {

    alarm_name = "web_cpu_alarm_down"
    comparison_operator = "LessThanOrEqualToThreshold"
    evaluation_periods = "2"
    metric_name = "CPUUtilization"
    namespace = "AWS/EC2"
    period = "120"
    statistic = "Average"
    threshold = "10"

    dimensions = {
      AutoScalingGroupName = aws_autoscaling_group.Mastercard_Asg.name
    }

    alarm_description = "This metric monitor EC2 instance CPU utilization"
    alarm_actions = [ aws_autoscaling_policy.web_server_down_policy.arn ]
  }

output "lb_dns_name"{
  value = aws_lb.external_lb.dns_name
  }
