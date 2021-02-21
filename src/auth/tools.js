const jwt = require("jsonwebtoken");
const User = require("../users/schema");

const authenticate = async (user) => {
  try {
    const newAccessToken = await generateJWT({ _id: user._id });
    const newRefreshToken = await generateRefreshJWT({ _id: user._id });

    user.refreshTokens = user.refreshTokens.concat({ token: newRefreshToken });
    await user.save();

    return { token: newAccessToken, refreshToken: newRefreshToken };
  } catch (error) {
    console.log(error);
    throw new Error(error);
  }
};

const generateJWT = (payload) =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: 6 },
      (err, token) => {
        if (err) rej(err);
        res(token);
      }
    )
  );

const verifyJWT = (token) =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) rej(err);
      res(decoded);
    })
  );

const generateRefreshJWT = (payload) =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.REFRESH_JWT_SECRET,
      { expiresIn: "1 week" },
      (err, token) => {
        if (err) rej(err);
        res(token);
      }
    )
  );

const verifyRefreshToken = (token) =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.REFRESH_JWT_SECRET, (err, decoded) => {
      if (err) rej(err);
      res(decoded);
    })
  );

const refreshToken = async (oldRefreshToken) => {
  //Verify old refresh token and recive back user holding it
  const decoded = await verifyRefreshToken(oldRefreshToken);
  //Find a user with that token
  const user = await User.findOne({ _id: decoded._id });
  //if there is no such user witt that id throw new error
  if (!user) {
    throw new Error(`Access is forbidden`);
  }

  //This is a check method to see if the current refresh token is in the users tokens array
  const currentRefreshToken = user.refreshTokens.find(
    (t) => t.token === oldRefreshToken
  );
  //And if it is not then throw a new error `Refresh token is wrong`
  if (!currentRefreshToken) {
    throw new Error(`Refresh token is wrong`);
  }

  //If everything is aight on this stage then generate new Access & Refresh token
  const newAccessToken = await generateJWT({ _id: user._id });
  const newRefreshToken = await generateRefreshJWT({ _id: user._id });

  //We create an array without the old refresh token and add the new one as an object { token: newRefreshToken }
  const newRefreshTokens = user.refreshTokens
    .filter((t) => t.token !== oldRefreshToken)
    .concat({ token: newRefreshToken });
  //We set this array as the users refresh Tokens array
  user.refreshTokens = [...newRefreshTokens];
  //We save the user in DB
  await user.save();
  //We return back both the Access & Refresh tokens
  return { token: newAccessToken, refreshToken: newRefreshToken };
};

module.exports = { authenticate, verifyJWT, refreshToken };
