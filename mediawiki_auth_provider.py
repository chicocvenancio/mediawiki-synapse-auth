from twisted.internet import defer
import mwoauth
import logging

from synapse.types import UserID


logger = logging.getLogger(__name__)


class MediawikiOAuthProvider:

    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        self.config = config
        self.auth_handler = self.account_handler._auth_handler

    @staticmethod
    def parse_config(config):
        # verify config sanity
        required = ["consumer_key", "consumer_secret"]
        missing = [key for key in required if key not in config]
        if missing:
            raise Exception((
                "Mediawiki OAuth enabled but missing required config values:"
                " {}").format(", ".join(missing))
            )

        class _MWConfig(object):
            oauth_mwuri = "https://meta.wikimedia.org/w/index.php"
            consumer_key = ""
            consumer_secret = ""
            domain = ""

        mw_config = _MWConfig()
        mw_config.consumer_key = config["consumer_key"]
        mw_config.consumer_secret = config["consumer_secret"]
        return mw_config

    @staticmethod
    def get_supported_login_types():

        return {"org.wikimedia.oauth_v1": ("request_key", "request_secret",
                                           "oauth_query")}

    @defer.inlineCallbacks
    def check_auth(self, user_id, login_type, login_dict):
        """Authenticate user with mediawiki

        This will receive OAuth comsumer and request tokens and identify
        the user. Initiating and handling the OAuth callback will be done
        in the clients"""

        logger.info("Request to auth user %s", user_id)
        consumer_token = mwoauth.ConsumerToken(
            self.config.consumer_key, self.config.consumer_secret)

        try:
            access_token = mwoauth.complete(
                self.config.oauth_mwuri, consumer_token,
                mwoauth.RequestToken(login_dict['request_key'],
                                     login_dict['request_secret']),
                login_dict['oauth_query'])

            identity = yield mwoauth.identify(
                self.config.oauth_mwuri, consumer_token, access_token)
        except Exception as e:
            logger.exception('OAuth authentication failed, %s', e)
            yield defer.returnValue(None)

        if user_id.startswith("@"):
            localpart = user_id.split(":", 1)[0][1:]
        else:
            localpart = user_id
            user_id = UserID(localpart, self.account_handler.hs.hostname
                             ).to_string()
        if localpart != identity["username"]:
            logger.error(("username from mediawiki differs from provided %s !="
                          "%s"), localpart, identity["username"])
            yield defer.returnValue(None)
        logger.info("User %s authenticated", user_id)
        if not (yield self.account_handler.check_user_exists(user_id)):
            logger.info("User %s does not exist yet, creating...", user_id)
            user_id, access_token = (yield self.account_handler.register(
                                     localpart=localpart))
            #  registration = True
            logger.info("Registration based on MW_OAuth was successful for %s",
                        user_id)
        else:
            logger.info("User %s already exists, registration skipped",
                        user_id)

        yield defer.returnValue((user_id, None))
