import { CookieOptions, Request, Response } from "express";
import config from "config";
import jwt from "jsonwebtoken";
import {
  createSession,
  findSessions,
  updateSession,
} from "../services/session.service";
import {
  findOneAndUpdate,
  getGoogleOAuthTokens,
  getGoogleUser,
  validatePassword,
} from "../services/user.service";
import { signJwt } from "../utils/jwt.utils";
import log from "../utils/logger";
import { UserDocument } from "../models/user.model";
import { Types } from "mongoose";

const accessTokenCookieOptions: CookieOptions = {
  maxAge: 90000, // 15 mins
  httpOnly: true,
  domain: "localhost",
  path: "/",
  sameSite: "lax",
  secure: false,
};

const refreshTokenCookieOptions: CookieOptions = {
  ...accessTokenCookieOptions,
  maxAge: 3.154e10, // 1 year
};

export async function createUserSessionHandler(req: Request, res: Response) {
  // validate the user's password
  const user = await validatePassword(req.body);

  if (!user) {
    return res.status(401).send("Invalid email or password");
  }

  // create a session
  const session = await createSession(user._id, req.get("user-agent") || "");

  // create an access token
  const accessToken = signJwt(
    {
      ...user,
      session: session._id,
    },
    { expiresIn: config.get("accessTokenTtl") } // 15 minutes
  );

  // create a refresh token
  const refreshToken = signJwt(
    {
      ...user,
      session: session._id,
    },
    { expiresIn: config.get("refreshTokenTtl") } // 1 year
  );

  // return access & refresh token
  res.cookie("accessToken", accessToken, accessTokenCookieOptions);

  res.cookie("refreshToken", refreshToken, refreshTokenCookieOptions);

  return res.send({ accessToken, refreshToken });
}

export async function getUserSessionsHandler(req: Request, res: Response) {
  const userId = res.locals.user._id;

  const sessions = await findSessions({ user: userId, valid: true });

  return res.send(sessions);
}

export async function deleteSessionHandler(req: Request, res: Response) {
  const sessionId = res.locals.user.session;

  await updateSession({ _id: sessionId }, { valid: false });

  return res.send({
    accessToken: null,
    refreshToken: null,
  });
}

export async function googleOAuthHandler(req: Request, res: Response) {
  // get the code from qs
  const code = req.query.code as string;

  try {
    // get the id and access token with code
    const { id_token, access_token } = await getGoogleOAuthTokens({ code });

    // get user with tokens
    const googleUser = await getGoogleUser({ id_token, access_token });
    // jwt.decode(id_token);

    if (!googleUser.verified_email) {
      return res.status(403).send("Google account is not verified");
    }

    // upsert the user
    const user = await findOneAndUpdate(
      {
        email: googleUser.email,
      },
      {
        email: googleUser.email,
        name: googleUser.name,
        picture: googleUser.picture,
      },
      {
        upsert: true,
        new: true,
      }
    );

    if (!user) {
      return res.status(404).send("Failed to upsert user");
    }

    // create a session
    const session = await createSession(user!._id, req.get("user-agent") || "");

    // create an access token
    const accessToken = signJwt(
      {
        ...user?.toJSON<UserDocument & { _id: Types.ObjectId }>(),
        session: session._id,
      },
      { expiresIn: config.get("accessTokenTtl") } // 15 minutes
    );

    // create a refresh token
    const refreshToken = signJwt(
      {
        ...user?.toJSON<UserDocument & { _id: Types.ObjectId }>(),
        session: session._id,
      },
      { expiresIn: config.get("refreshTokenTtl") } // 1 year
    );

    // set cookies
    res.cookie("accessToken", accessToken, accessTokenCookieOptions);

    res.cookie("refreshToken", refreshToken, {});

    // redirect back to client
    res.redirect(config.get("origin"));
  } catch (error: any) {
    log.error(error, "Failed to authorize Google User");
    return res.redirect(`${config.get("origin")}/oauth/error`);
  }
}
