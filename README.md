# AwsRawApi

## Description
This is a C# ASP.NET Web API project that interacts with AWS EC2 using **raw HTTP requests** (not the SDK).  
It can list EC2 instances across all regions using AWS Signature Version 4 for authentication.

## Features
- List all EC2 regions
- Get all EC2 instances in each region
- AWS Signature V4 signing implemented manually
- Returns JSON responses

## Prerequisites
- Valid AWS access key and secret key with EC2 permissions

## How to Run
1. Clone the repository
   
2. Open the project in Visual Studio or VS Code.

3. Set the project as the startup project.

4. Run the API.

5. Access endpoints via browser , swagger or Postman
