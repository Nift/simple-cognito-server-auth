import { Some } from "optional-typescript";
import * as AWS from "aws-sdk";
import * as jwt from "jsonwebtoken";
import * as jwkToPem from "jwk-to-pem";

// @ts-ignore
global.navigator = {
  userAgent: "NodeJS"
};

export interface ICognitoCredentials {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

export interface IAwsJwtToken {
  header: { kid: string; alg: string };
  payload: IAwsTokenPayload;
  signature: string;
}

export interface IAwsTokenPayload {
  sub: string;
  aud: string;
  email_verified: boolean;
  event_id: string;
  token_use: string;
  auth_time: number;
  iss: string;
  "cognito:username": string;
  exp: number;
  iat: number;
  email: string;
}

export async function validateAwsToken(
  credentials: ICognitoCredentials[],
  token: string
) {
  const decodedOrNone = Some(
    jwt.decode(token, {
      complete: true
    })
  ).map<IAwsJwtToken>(a => {
    if (typeof a === "string") {
      return JSON.parse(a);
    } else return a;
  });
  if (!decodedOrNone.hasValue) throw new Error("Not possible to authenticate");
  const decoded = decodedOrNone.valueOrFailure();
  const retrievedCredentialsOrNone = Some(
    credentials.find(a => a.kid === decoded.header.kid)
  );
  if (!retrievedCredentialsOrNone.hasValue) return false;
  const retrievedCredentials = retrievedCredentialsOrNone.valueOrFailure();
  const pem = jwkToPem(<jwkToPem.RSA>retrievedCredentials);
  try {
    const verifiedDecoded = <IAwsTokenPayload>jwt.verify(token, pem, {
      algorithms: ["RS256"]
    });
    return { userId: verifiedDecoded.sub, email: verifiedDecoded.email };
  } catch (error) {
    throw new Error("not possible to authenticate");
  }
}

export async function doesUserExist({
  region,
  userPoolId,
  username
}: {
  region: string;
  userPoolId: string;
  username: string;
}) {
  AWS.config.update({ region });
  const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();
  try {
    const user = await cognitoIdentityServiceProvider
      .adminGetUser({ Username: username, UserPoolId: userPoolId })
      .promise();
    return user !== undefined;
  } catch (error) {
    return false;
  }
}

export async function createUserSilently({
  region,
  userPoolId,
  clientId,
  username,
  password
}: {
  region: string;
  userPoolId: string;
  clientId: string;
  username: string;
  password: string;
}) {
  AWS.config.update({ region });
  const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();
  try {
    await cognitoIdentityServiceProvider
      .adminCreateUser({
        UserPoolId: userPoolId,
        Username: username,
        TemporaryPassword: password,
        MessageAction: "SUPPRESS",
        UserAttributes: [
          { Name: "email", Value: username },
          { Name: "email_verified", Value: "true" }
        ]
      })
      .promise();
    const signInRequest = await cognitoIdentityServiceProvider
      .adminInitiateAuth({
        AuthFlow: "ADMIN_NO_SRP_AUTH",
        ClientId: clientId,
        UserPoolId: userPoolId,
        AuthParameters: { USERNAME: username, PASSWORD: password }
      })
      .promise();
    if (
      signInRequest.ChallengeName !== "NEW_PASSWORD_REQUIRED" ||
      signInRequest.ChallengeParameters === undefined
    ) {
      console.warn("Password only set as temporary for user:", username);
      return true;
    }
    const successfullySetPassword = await cognitoIdentityServiceProvider
      .adminRespondToAuthChallenge({
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ClientId: clientId,
        UserPoolId: userPoolId,
        ChallengeResponses: {
          NEW_PASSWORD: password,
          USERNAME: signInRequest.ChallengeParameters.USER_ID_FOR_SRP
        },
        Session: signInRequest.Session
      })
      .promise();
    return successfullySetPassword !== undefined;
  } catch (error) {
    console.error("Error migrating a user silently", error);
    throw error;
  }
}