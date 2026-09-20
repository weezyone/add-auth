import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { UserModel } from '../models/User';
import { RoleModel } from '../models/Role';
import { appConfig } from './index';
import { logger } from '../utils/logger';

// Serialize user for session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await UserModel.findById(id);
    if (user) {
      const roles = await RoleModel.getUserRoles(user.id);
      done(null, { ...user, roles: roles.map(role => role.name) });
    } else {
      done(null, false);
    }
  } catch (error) {
    logger.error('Error deserializing user', { userId: id, error });
    done(error);
  }
});

// Google OAuth Strategy
if (appConfig.oauth.google.clientId && appConfig.oauth.google.clientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: appConfig.oauth.google.clientId,
        clientSecret: appConfig.oauth.google.clientSecret,
        callbackURL: `${appConfig.oauth.callbackUrl}/google`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          logger.info('Google OAuth profile received', {
            id: profile.id,
            email: profile.emails?.[0]?.value,
            name: profile.displayName,
          });

          // Check if user exists with this Google ID
          let user = await UserModel.findByOAuthProvider('google', profile.id);

          if (!user) {
            // Check if user exists with this email
            const email = profile.emails?.[0]?.value;
            if (email) {
              user = await UserModel.findByEmail(email);
              
              if (user) {
                // Link existing account with Google OAuth
                await UserModel.linkOAuthAccount(user.id, 'google', profile.id, {
                  accessToken,
                  refreshToken,
                  profile: {
                    id: profile.id,
                    displayName: profile.displayName,
                    emails: profile.emails,
                    photos: profile.photos,
                  },
                });
                
                logger.info('Linked existing account with Google OAuth', {
                  userId: user.id,
                  email: user.email,
                });
              } else {
                // Create new user with Google OAuth
                user = await UserModel.createFromOAuth({
                  provider: 'google',
                  providerId: profile.id,
                  email: email,
                  name: profile.displayName || email.split('@')[0],
                  emailVerified: true, // Google emails are verified
                  oauthData: {
                    accessToken,
                    refreshToken,
                    profile: {
                      id: profile.id,
                      displayName: profile.displayName,
                      emails: profile.emails,
                      photos: profile.photos,
                    },
                  },
                });

                // Assign default user role
                const defaultRole = await RoleModel.findByName('user');
                if (defaultRole) {
                  await RoleModel.assignToUser({
                    user_id: user.id,
                    role_id: defaultRole.id,
                    assigned_by: user.id, // Self-assigned for OAuth
                  });
                }

                logger.info('Created new user from Google OAuth', {
                  userId: user.id,
                  email: user.email,
                });
              }
            } else {
              return done(new Error('No email provided by Google'));
            }
          } else {
            // Update OAuth tokens
            await UserModel.updateOAuthTokens(user.id, 'google', {
              accessToken,
              refreshToken,
            });
            
            logger.info('Updated Google OAuth tokens for existing user', {
              userId: user.id,
            });
          }

          const roles = await RoleModel.getUserRoles(user.id);
          return done(null, { ...user, roles: roles.map(role => role.name) });
        } catch (error) {
          logger.error('Error in Google OAuth strategy', { error });
          return done(error);
        }
      }
    )
  );
}

// GitHub OAuth Strategy
if (appConfig.oauth.github.clientId && appConfig.oauth.github.clientSecret) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: appConfig.oauth.github.clientId,
        clientSecret: appConfig.oauth.github.clientSecret,
        callbackURL: `${appConfig.oauth.callbackUrl}/github`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          logger.info('GitHub OAuth profile received', {
            id: profile.id,
            username: profile.username,
            email: profile.emails?.[0]?.value,
            name: profile.displayName,
          });

          // Check if user exists with this GitHub ID
          let user = await UserModel.findByOAuthProvider('github', profile.id);

          if (!user) {
            // Check if user exists with this email
            const email = profile.emails?.[0]?.value;
            if (email) {
              user = await UserModel.findByEmail(email);
              
              if (user) {
                // Link existing account with GitHub OAuth
                await UserModel.linkOAuthAccount(user.id, 'github', profile.id, {
                  accessToken,
                  refreshToken,
                  profile: {
                    id: profile.id,
                    username: profile.username,
                    displayName: profile.displayName,
                    emails: profile.emails,
                    photos: profile.photos,
                  },
                });
                
                logger.info('Linked existing account with GitHub OAuth', {
                  userId: user.id,
                  email: user.email,
                });
              } else {
                // Create new user with GitHub OAuth
                user = await UserModel.createFromOAuth({
                  provider: 'github',
                  providerId: profile.id,
                  email: email,
                  name: profile.displayName || profile.username || email.split('@')[0],
                  emailVerified: true, // GitHub emails are verified
                  oauthData: {
                    accessToken,
                    refreshToken,
                    profile: {
                      id: profile.id,
                      username: profile.username,
                      displayName: profile.displayName,
                      emails: profile.emails,
                      photos: profile.photos,
                    },
                  },
                });

                // Assign default user role
                const defaultRole = await RoleModel.findByName('user');
                if (defaultRole) {
                  await RoleModel.assignToUser({
                    user_id: user.id,
                    role_id: defaultRole.id,
                    assigned_by: user.id, // Self-assigned for OAuth
                  });
                }

                logger.info('Created new user from GitHub OAuth', {
                  userId: user.id,
                  email: user.email,
                });
              }
            } else {
              return done(new Error('No email provided by GitHub'));
            }
          } else {
            // Update OAuth tokens
            await UserModel.updateOAuthTokens(user.id, 'github', {
              accessToken,
              refreshToken,
            });
            
            logger.info('Updated GitHub OAuth tokens for existing user', {
              userId: user.id,
            });
          }

          const roles = await RoleModel.getUserRoles(user.id);
          return done(null, { ...user, roles: roles.map(role => role.name) });
        } catch (error) {
          logger.error('Error in GitHub OAuth strategy', { error });
          return done(error);
        }
      }
    )
  );
}

export default passport;