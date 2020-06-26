
# README Prod Alarm Forwarder
# README SNOW-AWS integration demo

A Cloudformation template targeting to deploy the AWS serverless backend to interact with ServiceNow for user provisionning 
A Cloudformation template targeting to deploy the AWS serverless backend to interact with ServiceNow for user provisionning, some configuration must be done on your ServiceNow instance in order to use this template. 

To resume how it works, when you create a new_call object in ServiceNow, it will trigger a Business Rules which will send an Outbound Rest Message to a lambda function through API Gateway.
This function get two information from the ServiceNow new_call object : the short description and the sys_id
The short description can be use to transmit information and the sys_id is used to retrieve the original message in order to update it with SNOW API.

More complexe manipulations can be processed using the python pysnow library which is bundled with the lambda function, more information on the library is available [here](https://pysnow.readthedocs.io/en/latest/)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Improvement](#improvement)
- [Support](#support)

## Installation

**Version beta**: the template currently deploy one API gateway with a post method, two lambda functions, one in nodejs to authorize using the api only with the right credentials, one in python bundled with the pysnow library to process and update the request.
**Version beta**: the template currently deploys one API gateway with a post method, two lambda functions, one in nodejs to authorize using the api only with the right credentials, one in python bundled with the pysnow library to process and update the request.
The ServiceNow Configuration part must be done manually.

### ServiceNow pre-configurations

First you need to install the `Service Desk Call` extension which allows to create a large panel of requests and ticket from a same object, to do so go on: `https://[num_instance].service-now.com/v_plugin_list.do` and install the required plugin from the list.

You now need to create a new basic authentication profile to connect to api Gateway ( Oauth support is being researched ), for doing so go on `https://[num_instance].service-now.com/sys_auth_profile_basic_list.do` and select New, call the user api-gateway and give it a login and password.

Now in order to allow your lambda function to make modifications to ServiceNow records through API, you should configure a new Oauth Client. In the Navigation panel search for `System OAuth>Application Registry` and select New, when pressed for choice, choose `Create an OAuth API endpoint for external clients`, you should have a menu similar to the one below.

![SNOW OAuth Client](img/Capture.PNG)

Name it AWS, let the Client Secret empty so ServiceNow will create it and press submit. Now select back your Oauth Client object and write down the Client ID and Client Secret, you will need them.
Create a new ServiceNow User and give him the admin role so he can use the API.

### Launch the stack

The stack will ask you all the credentials configured above to interact with ServiceNow:

**APIPassword**: The password configured in the api-gateway authentication profile
**APIUser**: The login configured in the api-gateway authentication profile
**LambdaBackendBucket**: Bucket is stored your zip files
**LambdaBackendKey**: Path to the api.zip file
**SNOWID:**: ClientID of the ServiceNow Oauth client configured above
**SNOWInstance**: Name of your ServiceNow instance ( [num_instance] )
**SNOWPassword**: Password of a ServiceNow API user
**SNOWSecret**: Client Secret of the ServiceNow Oauth client configured above
**SNOWUser**: Name of a ServiceNow API user

# ServiceNow configuration

In the stack created resources, select the new API Gateway called ServiceNowAPI and copy the invoke URL of the POST method in the prod stage:

![API Gateway](img/api.PNG)

Back in ServiceNow, create a new Rest Message: `System Web Services > Outbound > REST Message`
Call it AWS and paste the endpoint copied above in the Endpoint field.
In the Authentication field, choose Basic and select the Basic auth profile created earlier.
Now create a New HTTP Method and call it post, select POST as HTTP method and past the previous API Gateway endpoint.
For authentication, select Inherit from parent and in HTTP Request, copy the HTTP Headers and HTTP Query Parameters from the screenshot below.

![SNOW Rest](img/snow.PNG)

Launch the Cloudformation Stack.
We pass some json parameters in the body of our request and will fill them with values of our newly created ticket to trigger the lambda in AWS.
Now create two new Variable Substitutions called short_desc and sysid and give them some test values, then select Test and you should have the same results as below with an HTTP status 200.

![Substitution Variables](img/var.PNG) ![Test](img/test.PNG)

Above the test link select now Preview Script Usage and copy the shown script, you will need it soon.

![Script](img/script.PNG)

Now in `System Definition > Business Rules` create a new Business Rule, name it for instance AWS Rest and for table new_call, then tick the Advanced box and complete the `When to run setting as shown below`, you can optionally add a filter condition, for example not to trigger the rule for specific users or group of users.

![Business Rule](img/br.PNG)

Finally, in the Advanced tab, past the previously copied script in the body of the function but overide our test values with the value of our newly created object:

```javascript
r.setStringParameterNoEscape('short_desc', current.short_description);
r.setStringParameterNoEscape('sysid', current.sys_id);
```

We're now ready for prime-time!

## Usage

Output: 
Let's now create a change request in Service `Desk > Calls > New Call` with some test values.

![Pre Test](img/pretest.PNG)

If you open back the request in `Desk > Calls > All Open Calls`, you will see it has been updated by the lambda function.

![Post Test](img/posttest.PNG)

## Improvement

The nodejs function for Basic Auth is pretty simple and could be deployed easily inline, however the InlineCode hasn't been merged yet in the master branch of the AWS SAM project [currently in develop only](https://github.com/awslabs/serverless-application-model/pull/447#issuecomment-413483722)

Once it will be done, I recommend to modify this part of the template:

```yaml
  AuthorizerLambda:
    Type: 'AWS::Serverless::Function'
    Properties:
      Handler: authorizer.handler
      Runtime: nodejs6.10
      CodeUri:
        Bucket: !Ref LambdaBackendBucket
        Key: authorizer.zip
```

By:

```yaml
  AuthorizerLambda:
    Type: 'AWS::Serverless::Function'
    Properties:
      Handler: authorizer.handler
      Runtime: nodejs6.10
      InlineCode: !Join
        - "\n"
        - - '"use strict";' 
          -  const AWS = require('aws-sdk');
          -  const login = process.env['LOGIN'];
          -  const pswd = process.env['PASWD'];
          -  exports.handler = function (event, context, callback) {
          -   var authorizationHeader = event.headers.Authorization;
          -
          -   if (!authorizationHeader) return callback('Unauthorized');
          -
          -   var encodedCreds = authorizationHeader.split(' ')[1];
          -   var plainCreds = (new Buffer(encodedCreds, 'base64')).toString().split(':');
          -   var username = plainCreds[0];
          -   var password = plainCreds[1];
          -
          -   if (!(username === login && password === pswd)) return callback ('Unauthorized');
          -
          -   var authResponse = buildAllowAllPolicy(event, username);
          -
          -   callback(null, authResponse);
          - "};"
          - function buildAllowAllPolicy (event, principalId) {
          -   var tmp = event.methodArn.split(':');
          -   var apiGatewayArnTmp = tmp[5].split('/');
          -   var awsAccountId = tmp[4];
          -   var awsRegion = tmp[3];
          -   var restApiId = apiGatewayArnTmp[0];
          -   var stage = apiGatewayArnTmp[1];
          -   var apiArn = 'arn:aws:execute-api:' + awsRegion + ':' + awsAccountId + ':' +
          -     restApiId + '/' + stage + '/*/*';
          -   const policy = {
          -     "principalId: principalId,"
          -     "policyDocument: {"
          -       "Version: '2012-10-17',"
          -       "Statement: ["
          -         "{"
          -           "Action: 'execute-api:Invoke',"
          -           "Effect: 'Allow',"
          -           "Resource: [apiArn]"
          -         "}"
          -       "]"
          -     "}"
          -   "};"
          -   return policy;
          - "}"
```
In order not to mess up more with S3 bucket location for this small function. 

## Support

Please [open an issue](https://confluence.gemalto.com/pages/viewpage.action?pageId=278568171) for support.
 297  api-stackset.yaml 
@@ -0,0 +1,297 @@
AWSTemplateFormatVersion: 2010-09-09
Outputs:
  API:
    Description: API for SNOW interraction
    Value: !Ref ServiceNowAPI
  BackendFunction:
    Description: Function receiving and parsing Output REST message from SNOW
    Value: !Ref BackendLambda
Parameters:
  LambdaBackendKey:
    Default: /path/to/api.zip
    MinLength: 1
    Type: String
    Description: Full path of the backend lambda function in the S3 bucket
    MaxLength: 127
  SNOWPassword:
    MinLength: 1
    Type: String
    Description: password of a valid SNOW API user
    MaxLength: 127
  SNOWInstance:
    MinLength: 1
    Type: String
    Description: Name of the ServiceNow instance
    MaxLength: 127
  APIUser:
    MinLength: 1
    Type: String
    Description: >-
      login to authenticate in API Gateway, must be in a SNOW Basic Auth
      Configuration element
    MaxLength: 127
  APIPassword:
    MinLength: 1
    Type: String
    Description: >-
      password to authenticate in API Gateway, must be in a SNOW Basic Auth
      Configuration element
    MaxLength: 127
  SNOWUser:
    MinLength: 1
    Type: String
    Description: login of a valid SNOW API user
    MaxLength: 127
  LambdaBackendBucket:
    MinLength: 1
    Type: String
    Description: Name of the S3 bucket where is the located backend lambda
    MaxLength: 127
  SNOWSecret:
    MinLength: 1
    Type: String
    Description: ServiceNow Client Secret to call the API
    MaxLength: 127
  SNOWID:
    MinLength: 1
    Type: String
    Description: ServiceNow ClientID to call the API
    MaxLength: 127
Description: Backend to interact with ServiceNow
Resources:
  AuthorizerLambda:
    Type: 'AWS::Lambda::Function'
    Properties:
      Code:
        S3Bucket: !Ref LambdaBackendBucket
        S3Key: authorizer.zip
      Description: API Gateway Basic http authorizer
      Tags:
        - Value: SAM
          Key: 'lambda:createdBy'
      MemorySize: 128
      Environment:
        Variables:
          LOGIN: !Ref APIUser
          PASWD: !Ref APIPassword
      Handler: authorizer.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 3
      Runtime: nodejs6.10
  ServiceNowAPIprodStage:
    Type: 'AWS::ApiGateway::Stage'
    Properties:
      DeploymentId: !Ref ServiceNowAPIDeployment7f0c900e95
      RestApiId: !Ref ServiceNowAPI
      StageName: prod
  ConfigLambdaPermissionAPI:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      Principal: apigateway.amazonaws.com
      FunctionName: !Ref BackendLambda
      SourceArn: !Join 
        - ''
        - - 'arn:aws:execute-api:'
          - !Ref 'AWS::Region'
          - ':'
          - !Ref 'AWS::AccountId'
          - ':'
          - !Ref ServiceNowAPI
          - /*/POST/
  ServiceNowAPIDeployment7f0c900e95:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref ServiceNowAPI
      Description: 'RestApi deployment id: 7f0c900e95922b412e4d834546e9e3101523ceb5'
      StageName: Stage
  LambdaExecutionRole:
    Type: 'AWS::IAM::Role'
    Properties:
      Path: /
      Policies:
        - PolicyName: cloudwatchLogging
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Action:
                  - 'logs:CreateLogGroup'
                  - 'logs:CreateLogStream'
                  - 'logs:PutLogEvents'
                Resource: 'arn:aws:logs:*:*:*'
                Effect: Allow
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Action:
              - 'sts:AssumeRole'
            Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
  ServiceNowAPI:
    Type: 'AWS::ApiGateway::RestApi'
    Properties:
      Body:
        info:
          version: '1.0'
          title: ServiceNowAPI
        paths:
          /:
            post:
              responses:
                '200':
                  description: 200 response
                  schema:
                    $ref: '#/definitions/Empty'
              security:
                - snow_lamb: []
              x-amazon-apigateway-integration:
                contentHandling: CONVERT_TO_TEXT
                responses:
                  default:
                    statusCode: '200'
                uri: !Join 
                  - ''
                  - - 'arn:aws:apigateway:'
                    - !Ref 'AWS::Region'
                    - ':lambda:path/2015-03-31/functions/'
                    - !GetAtt BackendLambda.Arn
                    - /invocations
                httpMethod: POST
                passthroughBehavior: when_no_templates
                requestTemplates:
                  application/json: >
                    ##  See
                    http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
                    ##  This template will pass through all parameters including
                    path, querystring, header, stage variables, and context
                    through to the integration endpoint via the body/payload
                    #set($allParams = $input.params())
                    {
                    "body-json" : $input.json('$'),
                    "params" : {
                    #foreach($type in $allParams.keySet())
                        #set($params = $allParams.get($type))
                    "$type" : {
                        #foreach($paramName in $params.keySet())
                        "$paramName" : "$util.escapeJavaScript($params.get($paramName))"
                            #if($foreach.hasNext),#end
                        #end
                    }
                        #if($foreach.hasNext),#end
                    #end
                    },
                    "stage-variables" : {
                    #foreach($key in $stageVariables.keySet())
                    "$key" : "$util.escapeJavaScript($stageVariables.get($key))"
                        #if($foreach.hasNext),#end
                    #end
                    },
                    "context" : {
                        "account-id" : "$context.identity.accountId",
                        "api-id" : "$context.apiId",
                        "api-key" : "$context.identity.apiKey",
                        "authorizer-principal-id" : "$context.authorizer.principalId",
                        "caller" : "$context.identity.caller",
                        "cognito-authentication-provider" : "$context.identity.cognitoAuthenticationProvider",
                        "cognito-authentication-type" : "$context.identity.cognitoAuthenticationType",
                        "cognito-identity-id" : "$context.identity.cognitoIdentityId",
                        "cognito-identity-pool-id" : "$context.identity.cognitoIdentityPoolId",
                        "http-method" : "$context.httpMethod",
                        "stage" : "$context.stage",
                        "source-ip" : "$context.identity.sourceIp",
                        "user" : "$context.identity.user",
                        "user-agent" : "$context.identity.userAgent",
                        "user-arn" : "$context.identity.userArn",
                        "request-id" : "$context.requestId",
                        "resource-id" : "$context.resourceId",
                        "resource-path" : "$context.resourcePath"
                        }
                    }
                type: aws
              consumes:
                - application/json
              produces:
                - application/json
        schemes:
          - https
        x-amazon-apigateway-gateway-responses:
          UNAUTHORIZED:
            responseParameters:
              gatewayresponse.header.WWW-Authenticate: '''Basic'''
            responseTemplates:
              application/json: '{"message":$context.error.messageString}'
            statusCode: 401
        basePath: /prod
        securityDefinitions:
          snow_lamb:
            x-amazon-apigateway-authtype: custom
            type: apiKey
            name: Authorization
            x-amazon-apigateway-authorizer:
              type: request
              authorizerResultTtlInSeconds: 0
              identitySource: method.request.header.Authorization
              authorizerUri: !Join 
                - ''
                - - 'arn:aws:apigateway:'
                  - !Ref 'AWS::Region'
                  - ':lambda:path/2015-03-31/functions/'
                  - !GetAtt AuthorizerLambda.Arn
                  - /invocations
            in: header
        definitions:
          Empty:
            type: object
            title: Empty Schema
        swagger: '2.0'
  ConfigLambdaPermissionAuth:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      Principal: apigateway.amazonaws.com
      FunctionName: !Ref AuthorizerLambda
      SourceArn: !Join 
        - ''
        - - 'arn:aws:execute-api:'
          - !Ref 'AWS::Region'
          - ':'
          - !Ref 'AWS::AccountId'
          - ':'
          - !Ref ServiceNowAPI
          - /authorizers/*
  BackendLambda:
    Type: 'AWS::Lambda::Function'
    Properties:
      Code:
        S3Bucket: !Ref LambdaBackendBucket
        S3Key: !Ref LambdaBackendKey
      Description: 'Get request from SNOW, process and update'
      Tags:
        - Value: SAM
          Key: 'lambda:createdBy'
      MemorySize: 128
      Environment:
        Variables:
          Instance: !Ref SNOWInstance
          psswd: !Ref SNOWPassword
          secret: !Ref SNOWSecret
          clientid: !Ref SNOWID
          user: !Ref SNOWUser
      Handler: api.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 3
      Runtime: python3.6
 BIN +112 KB img/Capture.PNG 
Binary file not shown.
 BIN +66.9 KB img/api.PNG 
Binary file not shown.
 BIN +53.6 KB img/br.PNG 
Binary file not shown.
 BIN +31.2 KB img/posttest.PNG 
Binary file not shown.
 BIN +31.3 KB img/pretest.PNG 
Binary file not shown.
 BIN +43.1 KB img/script.PNG 
Binary file not shown.
 BIN +37.4 KB img/snow.PNG 
Binary file not shown.
 BIN +32.7 KB img/test.PNG 
Binary file not shown.
 BIN +47.5 KB img/var.PNG 
Binary file not shown.
0 comments on commit 661e922
@hafsaleem
 
 
Leave a comment

Attach files by dragging & dropping, selecting or pasting them.
 You’re not receiving notifications from this thread.
© 2020 GitHub, Inc.
Terms
Privacy
Security
Status
Help
Contact GitHub
Pricing
API
Training
Blog
About
