#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "@aws-cdk/core";
import lambda = require("@aws-cdk/aws-lambda");
import { CdkLambdaACMEStack } from "../lib";
import path = require("path");

const app = new cdk.App();
new CdkLambdaACMEStack(app, "CdkLambdaACMEStack", {
  environment: {
    ACCOUNT_EMAIL: "", // [REQUIRED] ACME account email
    BUCKET: "", // [REQUIRED] Bucket name where keys and certificates are stored
    // staging directory url, useful for testing
    // DIRECTORY_URL: "https://acme-staging-v02.api.letsencrypt.org/directory",
    DIRECTORY_URL: "https://acme-v02.api.letsencrypt.org/directory",
    SENTRY_DSN: "",
  },
  // archive with lambda can be loaded from s3
  // code: lambda.Code.fromBucket(bucket-name, key)
  code: lambda.Code.fromAsset(path.join(__dirname, "../../lambda.zip")),
});
