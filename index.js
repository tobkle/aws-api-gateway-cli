#!/usr/bin/env node

const packageJson = require("./package.json");
const fs = require("fs");

// AWS SDK V3 Clients
const {
  CognitoIdentityProviderClient,
  AdminConfirmSignUpCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const {
  fromCognitoIdentityPool,
} = require("@aws-sdk/credential-provider-cognito-identity");

const { CognitoIdentityClient } = require("@aws-sdk/client-cognito-identity");

// Amazon Cognito Identity JS
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const apigClientFactory = require("aws-api-gateway-client").default;
const WindowMock = require("window-mock").default;

// Polyfills for amazon-cognito-identity-js
// use native fetch instead
global.fetch = fetch;
global.window = { localStorage: new WindowMock().localStorage };
global.navigator = () => null;

// Yargs Arguments
const argv = require("yargs")
  .option("username", {
    describe: "Username of the user",
    demandOption: true,
    type: "string",
  })
  .option("password", {
    describe: "Password of the user",
    demandOption: true,
    type: "string",
  })
  .option("user-pool-id", {
    describe: "Cognito user pool id",
    demandOption: true,
    type: "string",
  })
  .option("app-client-id", {
    describe: "Cognito user pool app client id",
    demandOption: true,
    type: "string",
  })
  .option("cognito-region", {
    describe: "Cognito region",
    default: "us-east-1",
    type: "string",
  })
  .option("identity-pool-id", {
    describe: "Cognito identity pool id",
    demandOption: true,
    type: "string",
  })
  .option("invoke-url", {
    describe: "API Gateway URL",
    demandOption: true,
    type: "string",
  })
  .option("api-gateway-region", {
    describe: "API Gateway region",
    default: "us-east-1",
    type: "string",
  })
  .option("api-key", {
    describe: "API Key",
    default: undefined,
    type: "string",
  })
  .option("path-template", {
    describe: "API path template",
    demandOption: true,
    type: "string",
  })
  .option("method", {
    describe: "API method",
    default: "GET",
    type: "string",
  })
  .option("params", {
    describe: "API request params",
    default: "{}",
    type: "string",
  })
  .option("additional-params", {
    describe: "API request additional params",
    default: "{}",
    type: "string",
  })
  .option("body", {
    describe: "API request body",
    default: "{}",
    type: "string",
  })
  .option("access-token-header", {
    describe: "Header to use to pass access token with request",
    type: "string",
  })
  .help("h")
  .alias("h", "help")
  .alias("v", "version")
  .version(packageJson.version)
  .wrap(null).argv;

// Cognito User Pool Daten
const poolData = {
  UserPoolId: argv.userPoolId,
  ClientId: argv.appClientId,
};

// User Pools
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

// Confirm the User, if it isn't
async function confirmUser(username) {
  const cognitoClient = new CognitoIdentityProviderClient({
    region: argv.cognitoRegion,
  });

  const params = {
    UserPoolId: argv.userPoolId,
    Username: username,
  };

  const command = new AdminConfirmSignUpCommand(params);

  try {
    await cognitoClient.send(command);
    console.log(`User ${username} was confirmed successfully.`);
  } catch (err) {
    console.error("Error during User Confirmation:", err.message || err);
    process.exit(1);
  }
}

// Authenticate with AuthFlow USER_SRP_AUTH
function authenticate(username, password) {
  return new Promise((resolve, reject) => {
    const authenticationDetails =
      new AmazonCognitoIdentity.AuthenticationDetails({
        Username: username,
        Password: password,
      });

    const userData = {
      Username: username,
      Pool: userPool,
    };

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    console.log("Authentifiziere mit USER_SRP_AUTH");

    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: (result) => {
        resolve({
          idToken: result.getIdToken().getJwtToken(),
          accessToken: result.getAccessToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
        });
      },
      onFailure: async (err) => {
        if (err.code === "UserNotConfirmedException") {
          console.log("User is not confirmed. Confirming user now...");
          try {
            await confirmUser(username);
            console.log("User confirmed. Retry authentication...");
          } catch (confirmErr) {
            console.error(
              "Error during User confirmation:",
              confirmErr.message || confirmErr
            );
          }
        } else {
          console.error("Authentication Error:", err.message || err);
        }
        reject(err);
      },
      newPasswordRequired: () => {
        reject(new Error("New password required"));
      },
      mfaRequired: () => {
        reject(new Error("MFA not supported"));
      },
      customChallenge: () => {
        reject(new Error("Custom Challenge not supported"));
      },
    });
  });
}

// get temporary credentials from CognitoIdentityPool
function getAwsCredentials(idToken) {
  console.log("getting temporary credentials....");

  const credentials = fromCognitoIdentityPool({
    client: new CognitoIdentityClient({ region: argv.cognitoRegion }),
    identityPoolId: argv.identityPoolId,
    logins: {
      [`cognito-idp.${argv.cognitoRegion}.amazonaws.com/${argv.userPoolId}`]:
        idToken,
    },
  });

  return credentials;
}

// do api call now
async function makeRequest(credentials, userTokens) {
  console.log("executing api call");

  try {
    const resolvedCredentials = await credentials();

    const apigClient = apigClientFactory.newClient({
      apiKey: argv.apiKey,
      accessKey: resolvedCredentials.accessKeyId,
      secretKey: resolvedCredentials.secretAccessKey,
      sessionToken: resolvedCredentials.sessionToken,
      region: argv.apiGatewayRegion,
      invokeUrl: argv.invokeUrl,
    });

    let body = {};
    if (argv.body.startsWith("@")) {
      const bodyFromFile = argv.body.slice(1);
      const contentFromFile = fs.readFileSync(bodyFromFile, "utf-8");
      body = JSON.parse(contentFromFile);
    } else {
      body = JSON.parse(argv.body);
    }

    const params = JSON.parse(argv.params);
    const additionalParams = JSON.parse(argv.additionalParams);

    if (argv.accessTokenHeader) {
      additionalParams.headers = {
        ...additionalParams.headers,
        [argv.accessTokenHeader]: userTokens.accessToken,
      };
    }

    const result = await apigClient.invokeApi(
      params,
      argv.pathTemplate,
      argv.method,
      additionalParams,
      body
    );
    console.dir({
      status: result.status,
      statusText: result.statusText,
      data: result.data,
    });
  } catch (error) {
    if (error.response) {
      console.dir({
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data,
      });
    } else {
      console.error("API-execution error:", error.message);
    }
  }
}

// MAIN
(async () => {
  try {
    const tokens = await authenticate(argv.username, argv.password);

    // no tokens if authentication not successfull
    if (!tokens) {
      console.error("Authentifizierung fehlgeschlagen.");
      process.exit(1);
    }

    const credentials = getAwsCredentials(tokens.idToken);

    await makeRequest(credentials, tokens);
  } catch (err) {
    console.error("Fehler:", err.message || err);
    process.exit(1);
  }
})();
