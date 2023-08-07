import { spawn } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import got from 'got';
import jwt from 'jsonwebtoken';
import path from 'path';
import proxy from '@fastify/http-proxy';

const __dirname = path.resolve();

// Customer-provided configuration
//const ORG_ID_18_CONFIG_VAR_NAME = 'SALESFORCE_ADDON_ORG_ID_18';
const HEROKU_SERVICE_URL_CONFIG_VAR_NAME = 'HEROKU_SERVICE_URL';
const HEROKU_SERVICE_PORT_CONFIG_VAR_NAME = 'HEROKU_SERVICE_PORT';
//const ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME = 'SALESFORCE_ADDON_ENCODED_PRIVATE_KEY';
//const PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME = 'PRIVATE_KEY_FILEPATH';
//const CONSUMER_KEY_CONFIG_VAR_NAME = 'SALESFORCE_ADDON_CONSUMER_KEY';
const DEBUG_PORT_CONFIG_VAR_NAME = 'DEBUG_PORT';
const RUNTIME_CLI_FILEPATH_CONFIG_VAR_NAME = 'RUNTIME_CLI_FILEPATH';
const SF_AUDIENCE_CONFIG_VAR_NAME = 'SF_AUDIENCE';

// Headers
const HEADER_REQUEST_ID = 'x-request-id';
const HEADER_HEROKU_SERVICE_REQUEST_CONTEXT = 'ce-sffncontext';
const HEADER_SALESFORCE_CONTEXT = 'ce-sfcontext';
const HEADER_EXTRA_INFO = 'x-extra-info';
const HEADER_ORG_ID_18 = 'x-org-id-18';
const REQUIRED_CLOUD_EVENT_HEADERS = ['ce-specversion', 'ce-id', 'ce-datacontenttype', 'ce-source', 'ce-type'];

// Other constants
const HEROKU_SERVICE_INVOCATION_TYPE_SYNC = 'com.salesforce.herokuservice.invoke.sync';
const HEROKU_SERVICE_INVOCATION_TYPE_ASYNC = 'com.salesforce.herokuservice.invoke.async';
const SANDBOX_AUDIENCE_URL = 'https://test.salesforce.com';
const PROD_AUDIENCE_URL = 'https://login.salesforce.com';

/**
 * Generic error thrower setting status code.
 *
 * @param msg
 * @param statusCode
 * @param requestId
 */
function throwError(msg, statusCode, requestId) {
    if (requestId) {
        msg = `[${requestId}] ${msg}`;
    }
    const err = new Error(msg);
    err.statusCode = statusCode;
    throw err;
}

/**
 * Encapsulates proxy config.
 */
export class Config {
    constructor(env) {
        this.env = env;
    }

    filter(env, regex) {
        const values = [];
        Object.keys(env).forEach((key) => {
            if (regex.test(key)) {
                values.push(env[key]);
            }
        });
        return values;
    }

    assemble() {
        this.proxyPort = this.env['PORT'] || 3000;
        this.runtimeCLIPath = this.env[RUNTIME_CLI_FILEPATH_CONFIG_VAR_NAME]
            || `${__dirname}/../node_modules/@heroku/sf-fx-runtime-nodejs/bin/cli.js`;
        this.herokuServicePort = this.env[HEROKU_SERVICE_PORT_CONFIG_VAR_NAME] || 8080;
        this.herokuServiceDebugPort = this.env[DEBUG_PORT_CONFIG_VAR_NAME];
        this.herokuServiceUrl = `${(this.env[HEROKU_SERVICE_URL_CONFIG_VAR_NAME] || 'http://localhost')}:${this.herokuServicePort}`;
        //this.orgId18 = this.env[ORG_ID_18_CONFIG_VAR_NAME];
        this.authorizedOrgId18s = this.filter(this.env, /(SALESFORCE_ADDON|SALESFORCEAUTH_([A-Z]*))_(00D[A-Za-z0-9]{15})_ORG_ID_18/);
        console.log(`Auhtorized orgs: ${JSON.stringify(this.authorizedOrgId18s)}`);
        this.authZConfig = {};
        this.authorizedOrgId18s.forEach((orgId) => {
            console.log(`Inspecting org: ${orgId}`);
            const consumerKeyRegEx = new RegExp(
                `(SALESFORCE_ADDON|SALESFORCEAUTH_([A-Z]*))_(${orgId.toUpperCase()})_CONSUMER_KEY`, 'g')
            const tmpConsumerKey = this.filter(this.env, consumerKeyRegEx);
            if (!tmpConsumerKey || tmpConsumerKey.length !== 1) {
                throw Error(`Did not find CONSUMER_KEY for authorized org ${orgId}`);
            }

            const encodedPrivateKeyRegEx = new RegExp(
                `(SALESFORCE_ADDON|SALESFORCEAUTH_([A-Z]*))_(${orgId.toUpperCase()})_ENCODED_PRIVATE_KEY`, 'g')
            const tmpEncodedPrivateKey = this.filter(this.env, encodedPrivateKeyRegEx);
            if (!tmpEncodedPrivateKey || tmpEncodedPrivateKey.length !== 1) {
                throw Error(`Did not find ENCODED_PRIVATE_KEY for authorized org ${orgId}`);
            }

            this.authZConfig[orgId] = {
                consumerKey: tmpConsumerKey[0],
                privateKey: Buffer.from(tmpEncodedPrivateKey[0], 'base64').toString('utf8')
            };
        });
        console.log(`AuthZConfig: ${JSON.stringify(this.authZConfig)}`);
        /*const encodedPrivateKey = this.env[ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME];
        if (encodedPrivateKey) {
            this.privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
        } else if (this.env[PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME]) {
            this.privateKey = readFileSync(this.env[PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME]);
        }*/

        //this.clientId = this.env[CONSUMER_KEY_CONFIG_VAR_NAME];
        this.audience = this.env[SF_AUDIENCE_CONFIG_VAR_NAME];

        return this;
    }

    validate() {
        const validateRequiredConfig = (name, value) => {
            if (!value) {
                throw Error(`Required config ${name} not found`);
            }
        }

        if (!existsSync(this.runtimeCLIPath)) {
            throw Error(`Function start CLI not found ${this.runtimeCLIPath}.  Ensure that herokuService's buildpack ./bin/compile was run.`);
        }

        /*validateRequiredConfig(ORG_ID_18_CONFIG_VAR_NAME, this.orgId18);
        validateRequiredConfig(HEROKU_SERVICE_PORT_CONFIG_VAR_NAME, this.herokuServicePort);
        validateRequiredConfig(`${ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME} or ${PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME}`,
            this.privateKey);
        validateRequiredConfig(CONSUMER_KEY_CONFIG_VAR_NAME, this.clientId);*/

        const misconfigurations = [];
        if (this.authorizedOrgId18s.length > 0) {
            this.authorizedOrgId18s.forEach((orgId) => {
                const orgAuthZConfig = this.authZConfig[orgId];
                if (!orgAuthZConfig) {
                    misconfigurations.push(`Missing authZ config for org ${orgId}`);
                } else {
                    if (!('consumerKey' in orgAuthZConfig)) {
                        misconfigurations.push(`Missing CONSUMER_KEY authZ config var for org ${orgId}`);
                    }

                    if (!('privateKey' in orgAuthZConfig)) {
                        misconfigurations.push(`Missing ENCODED_PRIVATE_KEY authZ config var for org ${orgId}`);
                    }
                }
            });
        }

        if (misconfigurations.length > 0) {
            throw Error(`Found misconfigured Salesforce authorizations: ${JSON.stringify(misconfigurations)}`);
        }

        return this;
    }
}
const config = new Config(process.env);

/**
 * Base context providing utilities for extending classes.
 */
class BaseContext {
    constructor(requestId) {
        this.requestId = requestId;
    }

    decodeAndParse(encodedContext) {
        const decodedContext = Buffer.from(encodedContext, 'base64').toString('utf8');
        return JSON.parse(decodedContext);
    }
}
/**
 * Header 'ce-sffncontext': Heroku Service request context.
 *
 * Eg:
 *  {
 *     'id': '00Dxx0000006IYJEA2-4Y4W3Lw_LkoskcHdEaZze-uuid-typescriptservice-2023-03-23T15:18:53.429-0700',
 *     'herokuServiceName': 'typescriptservice',
 *     'resource': 'https://...',
 *     'source': 'urn:event:from:salesforce/<instance>/<orgId>/<platform origin, eg apex>',
 *     'type': 'com.salesforce.herokuservice.invoke.sync',
 *     'requestTime': '2023-03-23T15:18:53.429-0700',
 *     'herokuServiceInvocationId': '<HerokuServiceAsyncInvocationRequest__c.ID>',
 *     'permissionSets': '[ 'MyPermissionSet' ]'
 *   }
 */
export class HerokuServiceContext extends BaseContext {
    constructor(requestId, encodedContext) {
        super(requestId);
        this.sfFnContext =  super.decodeAndParse(encodedContext);
        this.type = this.sfFnContext.type;
        this.herokuServiceName = this.sfFnContext.herokuServiceName;
        this.herokuServiceInvocationId = this.sfFnContext.herokuServiceInvocationId;
        this.permissionSets = this.sfFnContext.permissionSets;
        this.accessToken = this.sfFnContext.accessToken;
    }

    validate() {
        if (!(this.type === HEROKU_SERVICE_INVOCATION_TYPE_SYNC || this.type === HEROKU_SERVICE_INVOCATION_TYPE_ASYNC)) {
            throwError(`Invalid Heroku Service invocation type ${this.type}`, 400, this.requestId);
        }

        if (this.type === HEROKU_SERVICE_INVOCATION_TYPE_ASYNC && !this.herokuServiceInvocationId) {
            throwError('HerokuServiceAsyncInvocationRequest__c ID not provided for async invocation', 400, this.requestId);
        }

        if (this.permissionSets && !Array.isArray(this.permissionSets)) {
            throwError('Expected array of Permission Sets', 400, this.requestId);
        }
    }

    setAccessToken(accessToken) {
        this.accessToken = accessToken;
    }

    toJsonEncoded() {
        return Buffer.from(JSON.stringify(this), 'utf8').toString('base64');
    }
}

/**
 * 'userContext' part of header 'ce-sfcontext'.
 *
 *  Eg:
 *  {
 *      'orgId': '00Dxx0000006IYJ',
 *      'userId': '005xx000001X8Uz',
 *      'username': 'admin@example.com',
 *      'salesforceBaseUrl': 'https://na1.salesforce.com',
 *      'orgDomainUrl': 'https://mycompany.my.salesforce.com',
 * 	    'namespace': ''
 *   }
 */
export class UserContext extends BaseContext {
    constructor(requestId, userContext) {
        super(requestId);
        this.namespace = userContext.namespace;
        this.orgId = userContext.orgId;
        this.orgDomainUrl = userContext.orgDomainUrl;
        this.username = userContext.username;
    }

    validate() {
        if (!this.orgId) {
            throwError('Organization ID not provided', 400, this.requestId);
        }

        if (!this.username) {
            throwError('Username not provided', 400, this.requestId);
        }

        if (!this.orgDomainUrl) {
            throwError(`SalesforceBaseUrl not provided`, 400, this.requestId);
        }
    }
}

/**
 * Header 'ce-sfcontext': Salesforce context, ie the contexts of the requesting Organization and user.
 *
 * Eg:
 *  {
 *     'apiVersion': '57.0',
 *     'payloadVersion': '0.1',
 *     'userContext': ...UserContext...
 *   }
 */
export class SalesforceContext extends BaseContext {
    constructor(requestId, encodedContext) {
        super(requestId);
        const sfContext =  super.decodeAndParse(encodedContext);
        this.apiVersion = sfContext.apiVersion;
        this.userContext = new UserContext(requestId, sfContext.userContext);
    }

    validate() {
        if (!this.apiVersion) {
            throwError('API Version not provided', 400, this.requestId);
        }

        if (!this.userContext) {
            throwError('UserContext not provided', 400, this.requestId);
        }

        this.userContext.validate();
    }
}

/**
 * Handles HTTP requests.
 */
export class HttpRequestUtil {
    async request(url, opts, json = true) {
        return json ? await got(url, opts).json() : await got(url, opts);
    }
}

/**
 * Base request handler providing common sync and async handling.
 */
class BaseRequestHandler {
    constructor(config, request, reply) {
        this.config = config;
        this.request = request;
        this.reply = reply;
        this.requestId = this.request.headers[HEADER_REQUEST_ID];
        this.logger = this.request.log;
        this.httpRequestUtil = new HttpRequestUtil();
    }

    /**
     * Parse and validate 'ce-sffncontext' and 'ce-sfcontext' headers.  See FunctionContext and SalesforceContext.
     *
     * @returns {{sfFnContext: HerokuServiceContext, sfContext: SalesforceContext}}
     */
    parseAndValidateContexts() {
        const headers = this.request.headers;

        // Function request context
        const encodedFunctionContextHeader = headers[HEADER_HEROKU_SERVICE_REQUEST_CONTEXT];
        if (!encodedFunctionContextHeader) {
            throwError(`Function context header ${HEADER_HEROKU_SERVICE_REQUEST_CONTEXT} not found`, 400, this.requestId);
        }

        let sfFnContext;
        try {
            sfFnContext = new HerokuServiceContext(this.requestId, encodedFunctionContextHeader);
        } catch (err) {
            throwError(`Invalid ${HEADER_HEROKU_SERVICE_REQUEST_CONTEXT} format - expected base64 encoded header: ${err.message}`, 400, this.requestId);
        }
        sfFnContext.validate();

        // Salesforce context
        const encodedSalesforceContextHeader = headers[HEADER_SALESFORCE_CONTEXT];
        if (!encodedSalesforceContextHeader) {
            throwError(`Salesforce context header ${HEADER_SALESFORCE_CONTEXT} not found`, 400, this.requestId);
        }

        let sfContext;
        try {
            sfContext = new SalesforceContext(this.requestId, encodedSalesforceContextHeader);
        } catch (err) {
            throwError(`Invalid ${HEADER_SALESFORCE_CONTEXT} format - expected base64 encoded header: ${err.message}`, 400, this.requestId);
        }
        sfContext.validate();

        this.logger.info(`[${this.requestId}] Validated context headers - well done`);

        return {
            sfFnContext,
            sfContext
        };
    }

    /**
     * Expected headers:
     *  - x-request-id: request id generated by client that tracks the entire request/response
     *  - ce-specversion: version of CloudEvent schema
     *  - ce-id: see x-request-id
     *  - ce-source: source of request
     *  - ce-datacontenttype: data type of request
     *  - ce-type: type of request
     *  - ce-sfcontext: Salesforce context - context of invoking Organization
     *  - ce-sffncontext: context of Heroku Service request
     *
     * @returns {{requestId: string, requestProvidedAccessToken: string}}
     */
    parseAndValidateHeaders() {
        const headers = this.request.headers;

        if (!this.requestId) {
            throwError(`${HEADER_REQUEST_ID} not found`, 400);
        }

        if (!headers.authorization) { // TODO: Regex validate
            throwError('Authorization not found', 400, this.requestId);
        }
        if (!headers.authorization.startsWith('Bearer ')) {
            throwError('Invalid Authorization', 400, this.requestId);
        }

        const requestProvidedAccessToken = headers.authorization.substring(headers.authorization.indexOf(' ') + 1);
        if (!requestProvidedAccessToken) {
            throwError('Authorization accessToken not found', 400, this.requestId);
        }

        REQUIRED_CLOUD_EVENT_HEADERS.forEach((ce) => {
            if (!headers[ce]) {
                throwError(`${ce} header not found`, 400, this.requestId);
            }
        });

        this.logger.info(`[${this.requestId}] Validated request headers - looks good`);

        return {requestId: this.requestId, requestProvidedAccessToken};
    }

    /**
     * Assemble Salesforce API URI part.
     *
     * @param baseUrl
     * @param apiVersion
     * @param uriPart
     * @returns {string}
     */
    assembleSalesforceAPIUrl(baseUrl, apiVersion, uriPart) {
        return `${baseUrl}/services/data/v${apiVersion}${uriPart}`;
    }

    /**
     * Assemble Salesforce API Headers.
     *
     * @param accessToken
     * @returns {{Authorization: string, "Content-Type": string}}
     */
    assembleSalesforceAPIHeaders(accessToken) {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };
    }

    /**
     * Validate that requesting Organization is expected Organization (orgId18) by using given token to verify Organization info
     * provided by /userinfo API.
     *
     * Alternative approach that is simpler and efficient, but may not be as secure is to validate a
     * key sent by the client.
     *
     * @param instanceUrl
     * @param requestProvidedAccessToken
     * @returns {Promise<void>}
     */
    async validateCaller(instanceUrl, requestProvidedAccessToken) {
        const url = `${instanceUrl}/services/oauth2/userinfo`;
        const opts = {
            method: 'GET',
            headers: this.assembleSalesforceAPIHeaders(requestProvidedAccessToken),
            retry: {
                limit: 1
            }
        };

        // Get Org's info via /userinfo API
        let userInfo;
        try {
            userInfo = await this.httpRequest(url, opts);
        } catch (err) {
            throwError(`Unable to validate request (/userinfo): ${err.message}`, this.requestId);
        }

        if (!userInfo || !this.config.authorizedOrgId18s.includes(userInfo.organization_id)) {
            this.logger.warn(`Unauthorized caller from Organization ${userInfo.organization_id}, expected one of ${JSON.stringify(this.config.authorizedOrgId18s)}`);
            throwError('Unauthorized request', 401, this.requestId);
        }

        this.logger.info(`[${this.requestId}] Validated client - good to go`);
    }

    /**
     * Validate expected payload and that the Heroku Service invoker is of the expected org.
     *
     * @returns {Promise<{requestId: string, requestProvidedAccessToken: string, sfFnContext: HerokuServiceContext, sfContext: SalesforceContext}>}
     */
    async validate() {
        // Parse and validate request
        const { requestId, requestProvidedAccessToken} = this.parseAndValidateHeaders();

        // Parse and validate Heroku Service and salesforce contexts
        const { sfFnContext, sfContext} = this.parseAndValidateContexts();

        // Validate that the context's orgId matches the accessToken
        await this.validateCaller(sfContext.userContext.orgDomainUrl, requestProvidedAccessToken);

        return {requestId, requestProvidedAccessToken, sfFnContext, sfContext};
    }

    /**
     * Mint and return herokuService's token for requesting user using configured Connected App.
     *
     * If applicable, activate provided session-based Permission Set(s) to token.
     *
     * TODO: Consider caching tokens for given signature: user, connected app, session-based Permission(s).  If cached,
     *       use /services/oauth2/introspect to determine token validity (eg, timeout).
     *
     * @param sfFnContext
     * @param sfContext
     * @returns {Promise<String>}
     */
    async mintToken(sfFnContext, sfContext) {
        const authZConfig = this.config.authZConfig[sfContext.userContext.orgId];
        if (!authZConfig || !authZConfig.consumerKey || !authZConfig.privateKey) {
            const errMsg = `AuthZ config not found for org ${sfContext.userContext.orgId}`;
            this.logger.error(errMsg);
            throwError(errMsg, 403, this.requestId);
        }

        const url = `${sfContext.userContext.orgDomainUrl}/services/oauth2/token`;
        const isTest = (url.includes('.sandbox.') || url.includes('.scratch.'));

        const jwtOpts = {
            issuer: authZConfig.consumerKey,
            audience: this.config.audience || (isTest ? SANDBOX_AUDIENCE_URL : PROD_AUDIENCE_URL),
            algorithm: 'RS256',
            expiresIn: 360,
        }

        const signedJWT = jwt.sign({prn: sfContext.userContext.username}, authZConfig.privateKey, jwtOpts);
        const opts = {
            method: 'POST',
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
                // content-length set by request API
            },
            form: {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': signedJWT
            },
            retry: {
                limit: 1
            }
        };

        // Mint!
        this.logger.info(`[${this.requestId}] Minting Heroku Service ${isTest ? 'test ' : ' '}token for user ${sfContext.userContext.username}, audience ${jwtOpts.audience}, url ${url}, issuer ${jwtOpts.issuer.substring(0, 5)}...`);
        let mintTokenResponse;
        try {
            mintTokenResponse = await this.httpRequest(url, opts);
        } catch (err) {
            let errMsg;
            if (err.response) {
                const errResponse = JSON.parse(err.response.body);
                errMsg = `Unable to mint Heroku Service token: ${errResponse.error} (${errResponse.error_description})`;
                if (errMsg.includes('invalid_app_access') || errMsg.includes('user hasn\'t approved this consumer')) {
                    errMsg += `. Ensure that the target Connected App is set to "Admin approved users are pre-authorized" and user ${sfContext.userContext.username} is assigned to Connected App via a Permission Set`;
                }
            } else {
                errMsg = err.message;
            }

            this.logger.error(errMsg);
            throwError(errMsg, 403, this.requestId);
        }

        this.logger.info(`[${this.requestId}] Minted Heroku Service ${sfFnContext.herokuServiceName}'s token - hooray`);

        return {
            herokuServiceAccessToken: mintTokenResponse.access_token,
            instanceUrl: mintTokenResponse.instance_url
        };
    }

    /**
     * Activate session-based Permission Sets, if applicable.
     *
     * @param sfFnContext
     * @param sfContext
     * @param herokuServiceAccessToken
     * @returns {Promise<void>}
     */
    async activateSessionPermSet(sfFnContext, sfContext, herokuServiceAccessToken) {
        const permissionSets = sfFnContext.permissionSets;
        if (!permissionSets || permissionSets.length === 0) {
            this.logger.info(`[${this.requestId}] Skipping session-based Permission Sets activation`);
            return;
        }

        // Assemble /activateSessionPermSet API body
        const inputs = [];
        permissionSets.forEach(permissionSet => {
            if (permissionSet.includes('__')) {
                inputs.push({
                    PermSetNamespace: permissionSet.substring(0, permissionSet.indexOf('__')),
                    PermSetName: permissionSet.substring(permissionSet.indexOf('__') + 2)
                });
            } else {
                inputs.push({PermSetName: permissionSet});
            }
        });
        this.logger.debug(`[${this.requestId}] POST /actions/standard/activateSessionPermSet: ${JSON.stringify(inputs)}`);

        const url = this.assembleSalesforceAPIUrl(sfContext.userContext.orgDomainUrl,
                                                         sfContext.apiVersion,
                                                  '/actions/standard/activateSessionPermSet');
        const opts = {
            method: 'POST',
            headers: this.assembleSalesforceAPIHeaders(herokuServiceAccessToken),
            json: {inputs: inputs},
            retry: {
                limit: 1
            }
        };

        // Activate!
        let activations;
        try {
            activations = await this.httpRequest(url, opts);
        } catch (err) {
            let errMsg = err.response.body;
            try {
                const errResponses = JSON.parse(errMsg);
                if (errResponses && errResponses.length > 0) {
                    const errMsgs = [];
                    // FIXME: Do array collect or whatever
                    errResponses.forEach(errResponse => errResponse.errors.forEach(error => errMsgs.push(`${error.message} [${error.statusCode}]`)));
                    errMsg = errMsgs.join('; ')
                }
            } catch (parseErr) {
                // ignore
            }
            this.logger.error(errMsg);
            throwError(errMsg, err.statusCode || 503, this.requestId);
        }

        const failedActivations = activations.filter(activation => !activation.isSuccess);
        if (failedActivations && failedActivations.length > 0) {
            // TODO: If available, include failed PermissionSet names from response
            throwError(`Unable to activate session-based Permission Set(s) ${permissionSets.join(', ')}: ${JSON.stringify(failedActivations.map(failedActivation => failedActivation.errors))}`, 503, this.requestId);
        } else {
            this.logger.info(`[${this.requestId}] Activated session-based Permission Set(s): ${permissionSets.join(', ')} - yessir`);
        }
    }

    /**
     * Re-assemble the herokuService's context setting herokuService's accessToken.
     *
     * @param sfFnContext
     * @param herokuServiceAccessToken
     */

    prepareFunctionRequest(sfFnContext, herokuServiceAccessToken) {
        // Function's org-access token
        sfFnContext.setAccessToken(herokuServiceAccessToken);
        this.request.headers[HEADER_HEROKU_SERVICE_REQUEST_CONTEXT] = sfFnContext.toJsonEncoded();

        this.logger.info(`[${this.requestId}] Prepared Heroku Service ${sfFnContext.herokuServiceName}'s request - let's go`);
    }

    /**
     * Enrich request with herokuService's accessToken activating session-based Permission Sets, if applicable.
     *
     * @param sfFnContext
     * @param sfContext
     * @returns {Promise<void>}
     */
    async enrich(sfFnContext, sfContext) {
        // Mint token with configured Connected App
        const {herokuServiceAccessToken} = await this.mintToken(sfFnContext, sfContext);

        // Activate session-based Permission Sets, if applicable
        await this.activateSessionPermSet(sfFnContext, sfContext, herokuServiceAccessToken);

        // Set token on Heroku Service request context
        this.prepareFunctionRequest(sfFnContext, herokuServiceAccessToken);
    }

    async httpRequest(url, opts, json = true) {
        return await this.httpRequestUtil.request(url, opts, json);
    }
}

/**
 * Handles sync requests.
 */
export class SyncRequestHandler extends BaseRequestHandler {

    constructor(config, request, reply) {
        super(config, request, reply);
    }

    /**
     * Handle sync Heroku Service request.
     *
     * @returns {Promise<void>}
     */
    async handle() {
        const {requestId, sfFnContext, sfContext} = await this.validate();

        this.logger.info(`[${requestId}] Handling ${sfFnContext.type} request to Heroku Service '${sfFnContext.herokuServiceName}'...`);

        await this.enrich(sfFnContext, sfContext);

        this.logger.info(`[${requestId}] Sending ${sfFnContext.type} request to Heroku Service '${sfFnContext.herokuServiceName}'...`);
    }
}

/**
 * Handles async requests.
 */
export class AsyncRequestHandler extends BaseRequestHandler {

    constructor(config, request, reply) {
        super(config, request, reply);
    }

    /**
     * Handle async Heroku Service request.
     *
     * @returns {Promise<void>}
     */
    async handle() {
        const { requestId, sfFnContext, sfContext } = await this.validate();
        this.logger.info(`[${requestId}] Handling ${sfFnContext.type} request to Heroku Service '${sfFnContext.herokuServiceName}'...`);

        if (HEROKU_SERVICE_INVOCATION_TYPE_ASYNC !== sfFnContext.type) {
            throwError('Invalid request type', 400, requestId);
        }

        await this.enrich(sfFnContext, sfContext);

        // TODO: Validate HerokuServiceAsyncInvocationRequest__c access and existence

        this.logger.info(`[${requestId}] Sending ${sfFnContext.type} request to Heroku Service '${sfFnContext.herokuServiceName}'...`);
    }

    /**
     * Update  async request's associated HerokuServiceAsyncInvocationRequest__c w/ herokuService's response.
     *
     * @param sfFnContext
     * @param sfContext
     * @param herokuServiceResponse
     * @param statusCode
     * @param extraInfo
     * @returns {Promise<void>}
     */
    async updateAsyncFunctionResponse(sfFnContext, sfContext, herokuServiceResponse, statusCode, extraInfo) {
        const herokuServiceInvocationId = sfFnContext.herokuServiceInvocationId;
        const accessToken = sfFnContext.accessToken;
        const userContext = sfContext.userContext;
        const afirObjectName =
            `${userContext.namespace ? `${userContext.namespace}__` : ''}HerokuServiceAsyncInvocationRequest__c`;
        const uriPart = `/sobjects/${afirObjectName}/${herokuServiceInvocationId}`;
        const url = this.assembleSalesforceAPIUrl(sfContext.userContext.orgDomainUrl,
                                                  sfContext.apiVersion,
                                                  uriPart);
        const status = statusCode < 200 || statusCode > 299 ? 'ERROR' : 'SUCCESS';


        const afir = {};
        afir[`${userContext.namespace ? `${userContext.namespace}__` : ''}ExtraInfo__c`] = extraInfo;
        afir[`${userContext.namespace ? `${userContext.namespace}__` : ''}Response__c`] = herokuServiceResponse;
        afir[`${userContext.namespace ? `${userContext.namespace}__` : ''}Status__c`] = status;
        afir[`${userContext.namespace ? `${userContext.namespace}__` : ''}StatusCode__c`] = statusCode;
        this.logger.debug(`[${this.requestId}] POST ${uriPart}: ${JSON.stringify(afir)}`);

        const opts = {
            method: 'PATCH',
            headers: this.assembleSalesforceAPIHeaders(accessToken),
            json: afir,
            retry: {
                limit: 1
            }
        };

        // Update HerokuServiceAsyncInvocationRequest__c
        let response;
        try {
            response = await this.httpRequest(url, opts, false);
        } catch (err) {
            let errMsg = err.response ? err.response.body : err.message;
            if (errMsg.includes('The requested resource does not exist')) {
                errMsg += `. Ensure that user ${sfContext.userContext.username} has access to ${afirObjectName} [${herokuServiceInvocationId}].`;
            }

            this.logger.error(errMsg);
            throwError(errMsg, 503, this.requestId);
        }

        if (!response || response.statusCode !== 204) {
            this.logger.error(`[${this.requestId}] Unable to save Heroku Service ${sfFnContext.herokuServiceName} response to ${afirObjectName} [${herokuServiceInvocationId}]: ${JSON.stringify(response.errors.join(','))}`);
        } else {
            this.logger.info(`[${this.requestId}] Updated Heroku Service ${sfFnContext.herokuServiceName} response [${statusCode}] to ${afirObjectName} [${herokuServiceInvocationId}]`);
        }
    }

    /**
     * Handle async request invoking herokuService.
     *
     * @param sfFnContext
     * @returns {Promise<{body: string, extraInfo: string, statusCode: number}>}
     */
    async invokeFunction(sfFnContext) {
        this.logger.info(`[${this.requestId}] Invoking async Heroku Service ${sfFnContext.herokuServiceName}...`);

        const opts = {
            method: this.request.method,
            headers: this.request.headers,
            body: JSON.stringify(this.request.body)
        };

        const startMs = Date.now();
        let statusCode, body, extraInfo;
        try {
            // Invoke Heroku Service!
            const herokuServiceResponse = await this.httpRequest(this.config.herokuServiceUrl, opts, false);
            statusCode = herokuServiceResponse.statusCode;
            body = herokuServiceResponse.body;
            extraInfo = herokuServiceResponse.headers[HEADER_EXTRA_INFO];
        } catch (err) {
            const response = err.response
            this.logger.error(response);
            statusCode = response.statusCode;
            body = response.body;
            extraInfo = response.headers[HEADER_EXTRA_INFO];
        } finally {
            this.logger.info(`[${this.requestId} Invoked Heroku Service ${sfFnContext.herokuServiceName} in ${Date.now() - startMs}ms`);
        }

        return {
            body,
            extraInfo,
            statusCode
        };
    }
}

/**
 * Handles health check requests.
 */
export class HealthCheckRequestHandler extends BaseRequestHandler {

    constructor(request, reply) {
        super(request, reply);
        if (!this.requestId) {
            this.requestId = `healthcheck-${Date.now()}`;
        }
    }

    /**
     * Handle healthcheck Heroku Service request.
     *
     * @returns {Promise<void>}
     */
    async handle() {
        this.request.log.info('Handling Heroku Service /healthcheck request');

        const orgId18 = this.request.headers[HEADER_ORG_ID_18];
        if (!orgId18 || !this.config.authorizedOrgId18s.includes(orgId18)) {
            this.logger.warn(`[${this.requestId}] Unauthorized caller from Organization ${orgId18}, expected one of ${JSON.stringify(this.config.authorizedOrgId18s)}`);
            throwError('Unauthorized request', 401, this.requestId);
        }

        try {
            const herokuServiceResponse = await this.invokeFunction();
            this.reply.send(herokuServiceResponse.body).code(herokuServiceResponse.statusCode);
        } catch (err) {
            if (err.code && 'ECONNREFUSED' === err.code) {
                this.logger.warn(`[${this.requestId}] Function not up.  Attempting to restart...`);
                try {
                    (new FunctionServer(this.logger)).start();
                    function sleep(ms) {
                        return new Promise((resolve) => {
                            setTimeout(resolve, ms);
                        });
                    }
                    await sleep(5000);
                    const herokuServiceResponse = await this.invokeFunction();
                    this.reply.send(herokuServiceResponse.body).code(herokuServiceResponse.statusCode);
                } catch (err) {
                    this.reply.send(err.message).code(503);
                }
            } else {
                this.reply.send(err.message).code(503);
            }
        }
    }

    async invokeFunction() {
        this.request.headers['x-health-check'] = 'true';
        const opts = {
            method: 'POST',
            headers: this.request.headers
        };

        const startMs = Date.now();
        try {
            // Invoke Heroku Service!
            return await this.httpRequest(this.config.herokuServiceUrl, opts, false);
        } finally {
            this.logger.info(`[${this.requestId}] Invoked Heroku Service health check in ${Date.now() - startMs}ms`);
        }
    }
}

/**
 * Handles start the Heroku Service server.
 */
class FunctionServer {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    start() {
        const args = [
            this.config.runtimeCLIPath,
            'serve',
            `${__dirname}/..`,
            '-p',
            this.config.herokuServicePort
        ];
        this.logger.info(`Starting Heroku Service w/ args: ${args.join(' ')}`);

        if (this.config.herokuServiceDebugPort) {
            args.push('-d');
            args.push(this.config.herokuServiceDebugPort);
        }

        this.herokuServiceProcess = spawn('node', args,{});
        this.logger.info(`Started Heroku Service started on port ${this.config.herokuServicePort}, process pid ${this.herokuServiceProcess.pid}`);

        this.herokuServiceProcess.stdout.on('data', buff => {
            const line = buff.toLocaleString();
            this.logger.info(`[fn] ${line}`);
        });
        this.herokuServiceProcess.stderr.on('data', buff => {
            const line = buff.toLocaleString();
            this.logger.info(`[fn] ${line}`);
        });
        this.herokuServiceProcess.on('error', err => {
            this.logger.error(`[fn] Error starting Heroku Service: ${err.message}`);
        });
        this.herokuServiceProcess.on('exit', code => {
            this.logger.info(`Function process exited with code ${code}`);
            process.exit(1);
        });
    }
}

/**
 * Handles starting and configuring the proxy server.
 */
export class ProxyServer {
    constructor(fastify) {
        this.fastify = fastify;
        this.logger = fastify.log;
        this.herokuServiceServer = new FunctionServer(config, this.logger);
    }

    /**
     * Validate required configuration and start Heroku Service server.
     */
    validate() {
        config.assemble().validate();
    }

    /**
     * Configure Fastify routes and hook implementations.
     *
     * @returns {ProxyServer}
     */
    configure() {
        /**
         * Register 'http-proxy' plugin to handle validating and enriching sync requests.  The request is forwarded to
         * the herokuService.
         */
        this.fastify.register(proxy, {
            upstream: config.herokuServiceUrl,
            prefix: '/sync',
            // Validate and enrich sync requests
            preHandler: async (request, reply) => {
                const requestHandler = new SyncRequestHandler(config, request, reply);
                await requestHandler.handle();
            },
            replyOptions: {
                onError: (reply, error) => {
                    if (error.statusCode && 503 === error.statusCode) {
                        this.logger.warn('Function request failed with 503 - implement Heroku Service health check, restart (if necessary), and retry');
                    }
                    reply.send(error);
                }
            }
        });

        /**
         * Route to handle async requests.
         *
         * Requests are validate, a Heroku Service token is minted and apply to the request, and finally a response is
         * sent to disconnect the original request.  The 'onResponse' handler then makes a separate request to the herokuService.
         */
        this.fastify.post('/async', async (request, reply) => {
            const requestHandler = new AsyncRequestHandler(config, request, reply);
            await requestHandler.handle();
            reply.code(201);
        });

        /**
         * On response, handle async requests.  The original request was validated and enriched in the /async route handler.
         */
        this.fastify.addHook('onResponse', async (request, reply) => {
            if (reply.statusCode !== 201) {
                return;
            }

            const requestHandler = new AsyncRequestHandler(config, request, reply);
            const { sfFnContext, sfContext } = requestHandler.parseAndValidateContexts();
            if (sfFnContext && HEROKU_SERVICE_INVOCATION_TYPE_ASYNC === sfFnContext.type) {
                const {body, extraInfo, statusCode} = await requestHandler.invokeFunction(sfFnContext);
                await requestHandler.updateAsyncFunctionResponse(sfFnContext, sfContext, body, statusCode, extraInfo);
            }
        });

        /**
         * Route to check health of Heroku Service process.
         */
        this.fastify.register(proxy, {
            upstream: config.herokuServiceUrl,
            prefix: '/healthcheck',
            preHandler: async (request, reply) => {
                const requestHandler = new HealthCheckRequestHandler(request, reply);
                await requestHandler.handle();
            }
        });

        /**
         * If close is called, also kill Heroku Service server.
         */
        this.fastify.addHook('onClose', async (instance) => {
            if (this.herokuServiceServer && this.herokuServiceServer.herokuServiceProcess) {
                this.herokuServiceServer.herokuServiceProcess.kill();
            }
        });

        return this;
    }

    /**
     * Start Heroku Service server.
     *
     * @returns {ProxyServer}
     */
    startFunctionServer() {
        this.herokuServiceServer.start();
        return this;
    }

    /**
     * Start proxy.
     *
     * @returns {ProxyServer}
     */
    start() {
        this.fastify.listen({ host: '0.0.0.0', port: config.proxyPort }, async (err, address) => {
            if (err) {
                this.logger.error(err);
                process.exit(1);
            }
        });

        return this;
    }
}