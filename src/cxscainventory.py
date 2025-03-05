import csv
import os
from http import HTTPStatus
from shared.package.clients.cxhttpclient import HTTPForbiddenException
from shared.package.clients.cxhttpclient import HTTPTimeout
from shared.package.clients.cxhttpclient import HTTPUnauthorizedException
from shared.package.common import cxutils
from shared.package.common.cxcaches import CxCaches
from shared.package.common.cxconfig import cxconfig
from shared.package.common.cxcsv import CxCsv
from shared.package.common.cxdatetime import CxDatetime
from shared.package.common.cxlogging import DEBUG
from shared.package.common.cxlogging import cxlogger
from shared.package.common.cxparamfilters import CxParamFilters
from shared.package.cxsca.cxscahttpclient import CxScaHttpClient


# CONTENT SPLITTERS
SPLITTER: str = '|'
NOTESSPLITTER: str = ' | '

# STATUSES
SOK: int = 0
SWARNING: int = 1
SDANGER: int = 2
SFAILED: int = 3
STATUS: list[str] = ['OK', 'WARNING', 'DANGER', 'FAILED']

# HTTP RELATED EXCEPTIONS
SFORBIDDEN: str = 'Insufficient permissions to get this data'
SEXCEPTION: str = 'Failed to get this data'

# CACHE NAMES FOR DATA
CACHE_CONFIG: str = 'CACHE-CONFIG'
CACHE_TEAMS: str = 'CACHE-TEAMS'

# CACHE NAMES INTERNAL
CACHE_AC_PROVIDERS: str = 'CACHE-AC-PROVIDERS'
CACHE_AC_USERS: str = 'CACHE-AC-USERS'
CACHE_AC_TEAMS: str = 'CACHE-AC-TEAMS'
CACHE_SCAN_ORIGINS: str = 'CACHE-SCAN-ORIGINS'

# CONFIGURATION OUTPUT OBJECT TYPES
OBJ_SCA_INSTANCE: str = 'CXONE-INSTANCE'
# IAM ACCESS-CONTROL OUTPUT OBJECT TYPES
OBJ_AC_USERS: str = 'AC-USERS'
OBJ_AC_USERS_APP: str = 'AC-USERS-APPLICATION'
OBJ_AC_USERS_SAML: str = 'AC-USERS-SAML'
OBJ_AC_USERS_MASTERAC: str = 'AC-USERS-MASTER-AC'
OBJ_AC_USERS_EMAILS: str = 'AC-USERS-EMAIL-DOMAINS'
OBJ_AC_TEAMS: str = 'AC-TEAMS'
OBJ_AC_ROLES: str = 'AC-ROLES'
OBJ_AC_SAML: str = 'AC-SAML-SETTINGS'
OBJ_AC_MASTER_AC: str = 'AC-MASTER-ACCESS'
# PROJECTS
OBJ_PROJECTS: str = 'PROJECTS'
# OTHER
OBJ_SCAN_ORIGINS: str = 'SCAN-ORIGINS'

# INVENTORY CSV OUTPUT FILES
OUT_SUMMARY: str = 'sca_inventorysummary.csv'
OUT_CONFIG: str = 'sca_inventoryconfigurations.csv'
OUT_ACUSERS: str = 'sca_inventoryusers.csv'
OUT_ACTEAMS: str = 'sca_inventoryteams.csv'
OUT_ACROLES: str = 'sca_inventoryroles.csv'
OUT_PROJECTS: str = 'sca_inventoryprojects.csv'

# CSV FILES HEADERS
CSV_SUMMARY: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-COUNT', 'NOTES']
CSV_CONFIG: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-ID', 'OBJ-NAME', 'OBJ-REF', 'PROJ-USING', 'NOTES']
CSV_ACUSERS: list[str] = ['STATUS', 'ID', 'NAME', 'EMAIL', 'FIRST-NAME', 'LAST-NAME', 'PROVIDER-TYPE', 'NOTES']
CSV_ACTEAMS: list[str] = ['STATUS', 'TEAM-ID', 'TEAM-NAME', 'PROJ-USING', 'NOTES']
CSV_ACROLES: list[str] = ['STATUS', 'ROLE-ID', 'ROLE-NAME', 'NOTES']
CSV_PROJECTS: list[str] = ['STATUS', 'ID', 'NAME', 'CREATED-ON', 'UPDATED-ON', 'EXPLOITABLE-PATH', 'LAST-SAST-SCAN', 'BRANCH', 'IS-MANAGED',
                           'LAST-SCAN', 'TAGS', 'TEAMS',
                           'RISK-REPORT-ID', 'RISK-REPORT-CREATED', 'RISK-REPORT-UPDATED',
                           'DIRECT-PACKAGES', 'TOTAL-PACKAGES', 'OUTDATED-PACKAGES',
                           'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'IGNORED', 'TRIAGES',
                           'SCAN-ORIGIN', 'MANIFEST-UPLOADED', 'LAST-SCANNED', 'SEVERITY', 'IS-VIOLATED', 'IS-PRIVATE', 'NOTES' ]


class CxScaInventory(object) :

    def __init__(self ) :
        self.__cxsca: CxScaHttpClient = None
        self.__cxcsv: CxCsv = CxCsv()
        self.__cxcaches: CxCaches = CxCaches()
        self.__datapath: str = None
        # # Tenant Id
        # self.__tenantid: str = None
        # Global execution options
        self.__noiam: bool = cxconfig.getvalue( "options.no-iam" )
        self.__noiam = self.__noiam and isinstance(self.__noiam, bool)
        self.__usersfull: bool = cxconfig.getvalue( "options.detailed-users" )
        self.__usersfull = self.__usersfull and isinstance(self.__usersfull, bool)
        self.__noscandata: bool = cxconfig.getvalue( "options.no-scans" )
        self.__noscandata = self.__noscandata and isinstance(self.__noscandata, bool)
        self.__notriages: bool = cxconfig.getvalue( "options.no-triages" )
        self.__notriages = self.__notriages and isinstance(self.__notriages, bool)
        self.__projectfilter: any = cxconfig.getvalue( "options.projects-filter" )
        # Well known file for csv containing summary
        self.__sumryhandler = None
        self.__sumrywriter = None
        # Well known file for csv containing system configurations
        self.__confhandler = None
        self.__confwriter = None
        # Well known file for csv containing access-control users
        self.__usershandler = None
        self.__userswriter = None
        # Well known file for csv containing access-control teams
        self.__teamshandler = None
        self.__teamswriter = None
        # Well known file for csv containing access-control roles
        self.__roleshandler = None
        self.__roleswriter = None
        # Well known file for csv containing projects
        self.__projshandler = None
        self.__projswriter = None


    @property
    def cxsca(self) -> CxScaHttpClient :
        return self.__cxsca


    @property
    def aclhost(self) -> str :
        return self.cxsca.aclhost


    @property
    def tenant(self) :
        return self.cxsca.tenant


    @property
    def cxcsv(self) -> CxCsv :
        return self.__cxcsv


    @property
    def cxcaches(self) -> CxCaches :
        return self.__cxcaches


    def __dateparse(self, datetimestr: str) -> str :
        if not datetimestr :
            return datetimestr
        xdatestr: str = datetimestr.replace( 'T', ' ' )
        xdatestr = xdatestr.replace( 'Z', '' )
        xdotpos: int = xdatestr.find('.')
        if xdotpos > 0 :
            xdatestr = xdatestr[: xdotpos ]
        return xdatestr


    def __preparedatafiles(self) :
        # location path
        try :
            self.__closedatafiles()
            self.__datapath = cxutils.application_path()
            if not self.__datapath :
                self.__datapath = 'data'
            else :
                self.__datapath = self.__datapath + os.sep + 'data'
            os.makedirs(self.__datapath, exist_ok = True)
            cxlogger.debug( 'Output files location set to "' + self.__datapath + '"' )
            # Well known file for csv containing summary
            filename = self.__datapath + os.sep + OUT_SUMMARY
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing system configurations
            filename = self.__datapath + os.sep + OUT_CONFIG
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control users
            filename = self.__datapath + os.sep + OUT_ACUSERS
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control teams
            filename = self.__datapath + os.sep + OUT_ACTEAMS
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control roles
            filename = self.__datapath + os.sep + OUT_ACROLES
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing projects
            filename = self.__datapath + os.sep + OUT_PROJECTS
            if os.path.exists(filename) :
                os.remove(filename)
            # Done
            cxlogger.debug( 'Output files reset' )
            return True
        except Exception as e:
            cxlogger.exception(e)
            return False


    def __closedatafiles(self) :
        if (self.__sumryhandler):
            self.__sumryhandler.close()
        if (self.__confhandler):
            self.__confhandler.close()
        if (self.__usershandler):
            self.__usershandler.close()
        if (self.__teamshandler):
            self.__teamshandler.close()
        if (self.__roleshandler):
            self.__roleshandler.close()
        if (self.__projshandler):
            self.__projshandler.close()
        self.__sumryhandler = None
        self.__confhandler = None
        self.__usershandler = None
        self.__teamshandler = None
        self.__roleshandler = None
        self.__projshandler = None


    def __initconnection(self) :
        xstatus: bool = True
        xstarted = CxDatetime.now()
        cxlogger.info( 'Connecting to SCA' )

        try :

            # Initialize sast rest/odata connection
            self.__cxsca = CxScaHttpClient( fqdn = cxconfig.getvalue( "sca.url" ),
                                    tenant = cxconfig.getvalue( "sca.tenant" ),
                                    username = cxconfig.getvalue( "sca.username" ),
                                    password = cxconfig.getvalue( "sca.password" ),
                                    aclfqdn = cxconfig.getvalue( "sca.iamurl" ),
                                    certverify = not bool( cxconfig.getvalue( "sca.insecure" ) ),
                                    proxy_url = cxconfig.getvalue( "sca.proxy_url" ),
                                    proxy_username = cxconfig.getvalue( "sca.proxy_username" ),
                                    proxy_password = cxconfig.getvalue( "sca.proxy_password" ) )

            # Validate connection and authentication
            try:
                cxlogger.debug( "Connecting to SCA and authenticating" )
                self.cxsca.connect()
            except HTTPUnauthorizedException as ne :
                cxlogger.error( 'Unauthorized to connect to SCA')
                cxlogger.exception( ne, level = DEBUG )
                xstatus = False
                raise ne
            except Exception as e :
                cxlogger.error( 'Unable to connect to SCA')
                cxlogger.exception( e, level = DEBUG )
                xstatus = False

            if xstatus :
                # Validate required permissions
                # Access-control data
                #       Access Control Manager (all)
                #       User Manager, Teams Manager, or User and Teams Manager
                #       Manage Authentication Providers
                # SCA
                #       SCAT Admin (all)
                #       View Results
                cxlogger.debug( "Checking current user permissions" )
                perm_error: list[str] = []
                perm_warns: list[str] = []
                cxscaperms: dict = self.cxsca.userpermissions(includeteams = True)
                if len(cxscaperms['iam']) == 0 :
                    perm_error.append("Can't resolve user permissions, missing user manager role!")
                else :
                    if not ( 'manage-users' in cxscaperms['iam'] or 'manage-teams' in cxscaperms['iam'] ):
                        perm_warns.append("User is not authorized to retrieve users and teams data!")
                    # Check root team membership
                    if 'CxServer' not in cxscaperms['teams'] :
                        perm_warns.append( "User is not a member of CxServer team. Data may be incomplete!" )
                    # Check admin permissions for access-control layer (except if --no-iam flag is set)
                    if not self.__noiam :
                        if 'manage-authentication-providers' not in cxscaperms['iam'] :
                            perm_warns.append( "User is not authorized to retrieve authentication providers data!" )
                        if 'manage-roles' not in cxscaperms['iam'] :
                            perm_warns.append("User is not authorized to retrieve roles data!")
                    # Check view permissions
                    if 'view' not in cxscaperms['sca'] :
                        perm_error.append( "User is not authorized to view projects data which is required!" )

                # Fail mandatory permissions missing
                if len(perm_error) > 0 :
                    for msg_str in perm_error :
                        cxlogger.error( msg_str )
                    xstatus = False
                # Warn recommended permissions missing
                elif len(perm_warns) > 0:
                    for msg_str in perm_warns :
                        cxlogger.warning( msg_str )

        finally :
            if xstatus :
                cxlogger.info('Connected to SCA, ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return xstatus


    def __internal_write_summary( self, data: list ) :
        # Check output file is ready
        if not self.__sumryhandler :
            filename = self.__datapath + os.sep + OUT_SUMMARY
            self.__sumryhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__sumrywriter = csv.writer(self.__sumryhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__internal_write_summary(CSV_SUMMARY)
        # Write it
        self.__sumrywriter.writerow( data )


    def __internal_get_identity_providertype_ids(self, providertype: str) -> int :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsca.get(self.cxsca.aclhost + '/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xproviderids: list[int] = []
        if xproviders :
            xproviderslist = list( filter( lambda el: el['providerType'] == providertype, xproviders) )
            for xprovider in xproviderslist :
                xproviderids.append(xprovider['id'])
        return xproviderids


    def __internal_get_identity_provider_name(self, providerid: int) -> str :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsca.get(self.cxsca.aclhost + '/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xprovider: dict = None
        xprovidername: str = None
        if xproviders :
            xprovider = next( filter( lambda el: el['id'] == providerid, xproviders), None )
        if xprovider :
            xprovidername = xprovider.get('name')
        if not xprovidername :
            xprovidername = None
        return xprovidername


    def __internal_get_identity_provider_id(self, providername: str, providertype: str) -> int :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsca.get(self.cxsca.aclhost + '/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xproviderid: int = 0
        if xproviders :
            xprovider = next( filter( lambda el: el['name'] == providername and el['providerType'] == providertype, xproviders), None )
            if xprovider :
                xproviderid = xprovider['id']
        return xproviderid


    def __internal_get_all_active_users(self, ignoreerrors: bool = False) -> list[dict] :
        xallusers: list = self.cxcaches.cache(CACHE_AC_USERS)
        if not xallusers :
            xallusers = []
            try :
                xusers: list = self.cxsca.get( self.cxsca.aclhost + '/users')
                # filter only active
                xallusers = list( filter( lambda el: el['active'], xusers) )
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_AC_USERS, cachedata = xallusers )
        return xallusers


    def __internal_get_all_teams(self, ignoreerrors: bool = False) -> list[dict] :
        xallteams: list = self.cxcaches.cache(CACHE_AC_TEAMS)
        if not xallteams :
            xallteams = []
            try :
                xallteams: list = self.cxsca.get( self.cxsca.aclhost + '/teams')
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_AC_TEAMS, cachedata = xallteams )
        return xallteams


    def __internal_write_config( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__confhandler :
            filename = self.__datapath + os.sep + OUT_CONFIG
            self.__confhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__confwriter = csv.writer(self.__confhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__confwriter.writerow(CSV_CONFIG)
        # Write it
        self.__confwriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_CONFIG :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_CONFIG)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_CONFIG, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_user( self, data: list ) :
        # Check output file is ready
        if not self.__usershandler :
            filename = self.__datapath + os.sep + OUT_ACUSERS
            self.__usershandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__userswriter = csv.writer(self.__usershandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__userswriter.writerow(CSV_ACUSERS)
        # Write it
        self.__userswriter.writerow( data )


    def __internal_write_team( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__teamshandler :
            filename = self.__datapath + os.sep + OUT_ACTEAMS
            self.__teamshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__teamswriter = csv.writer(self.__teamshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__teamswriter.writerow(CSV_ACTEAMS)
        # Write it
        self.__teamswriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_ACTEAMS :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_TEAMS)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_TEAMS, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_role( self, data: list ) :
        # Check output file is ready
        if not self.__roleshandler :
            filename = self.__datapath + os.sep + OUT_ACROLES
            self.__roleshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__roleswriter = csv.writer(self.__roleshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__roleswriter.writerow(CSV_ACROLES)
        # Write it
        self.__roleswriter.writerow( data )


    def __inventory_scainstance(self) :
        errorcount = 0
        errorcount: int = 0
        inventory_name: str = 'sca instance'
        xobject: str = OBJ_SCA_INSTANCE
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            cxonename = 'SCA ' + cxconfig.getvalue( "sca.tenant" )
            # Register to inventory
            self.__internal_write_config( [STATUS[xstatus], xobject, None, cxonename, None, None, xinfo ] )
            # Register to summary
            if xinfo :
                xinfo = cxonename + ', ' + xinfo
            else :
                xinfo = cxonename
            self.__internal_write_summary( [STATUS[xstatus], xobject, 1, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (1) - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_users(self) :
        errorcount = 0
        inventory_name = 'access-control users'
        xobject: str = OBJ_AC_USERS
        xstatus: int = SWARNING

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xemaildomains: list[str] = []
        xemail: str = None
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Go for the users cache
            xallusers = self.__internal_get_all_active_users()

            # Application users
            xproviders = self.__internal_get_identity_providertype_ids('Application')
            xcounter = 0
            xinfo = 'application user'
            xobject = OBJ_AC_USERS_APP
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' users for manual creation'
            elif xcounter == 1 :
                xinfo = '1 user for manual creation'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # SAML users
            xproviders = self.__internal_get_identity_providertype_ids('SAML')
            xcounter = 0
            xinfo = 'SAML user'
            xobject = OBJ_AC_USERS_SAML
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' users for SAML integration'
            elif xcounter == 1 :
                xinfo = '1 user for SAML integration'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Master Access Control
            xproviders = self.__internal_get_identity_providertype_ids('MasterAccessControl')
            xcounter = 0
            xinfo = 'SAST user (master access control)'
            xobject = OBJ_AC_USERS_MASTERAC
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' SAST (master access control) users for manual creation'
            elif xcounter == 1 :
                xinfo = '1 SAST (master access control) user for manual creation'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Distinct email domains
            xinfo = 'distinct email domain'
            xemaildomains = list( dict.fromkeys(xemaildomains) )
            xobject = OBJ_AC_USERS_EMAILS
            if len(xemaildomains) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for email in xemaildomains :
                self.__internal_write_config( [STATUS[xstatus], xobject, None, email, None, None, xinfo ], False )
            # Register index
            xinfo = 'distinct email domains'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xemaildomains), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xallusers)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_teams(self) :
        errorcount = 0
        inventory_name = 'access-control teams'
        xobject: str = OBJ_AC_TEAMS
        xstatus: int = SOK

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xusercount: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xteams = self.__internal_get_all_teams()
            xusers = self.__internal_get_all_active_users(True)
            # Register to inventory
            for team in xteams :
                # Have users
                xusercount = 0
                if len(xusers) :
                    xusercount = len(list( filter( lambda el: team['id'] in el['teamIds'], xusers ) ))
                if xusercount > 1 :
                    xinfo = str(xusercount) + ' members'
                elif xusercount == 1 :
                    xinfo = str(xusercount) + ' member'
                else :
                    xinfo = 'no members'
                self.__internal_write_team( [STATUS[xstatus], team['id'], team['fullName'], None, xinfo ])

            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xteams), None ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xteams)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_roles(self) :
        errorcount = 0
        inventory_name = 'access-control roles'
        xobject: str = OBJ_AC_ROLES
        xstatus: int = SOK
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xusercount: int = 0
        xcustomroles: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xroles = self.cxsca.get( self.cxsca.aclhost + '/roles')
            xusers = self.__internal_get_all_active_users(True)
            # Register to inventory
            for role in xroles :
                xstatus = SOK
                # Have users
                xusercount = 0
                if len(xusers) > 0 :
                    xusercount = len(list( filter( lambda el: role['id'] in el['roleIds'], xusers ) ))
                if xusercount > 1 :
                    xinfo = str(xusercount) + ' members'
                elif xusercount == 1 :
                    xinfo = str(xusercount) + ' member'
                else :
                    xinfo = 'no members'
                if not role['isSystemRole'] :
                    xstatus = SWARNING
                    xinfo = 'custom role ' + xinfo
                    xcustomroles += 1
                self.__internal_write_role( [STATUS[xstatus], role['id'], role['name'], xinfo ])
            # Register index
            if xcustomroles > 0 :
                xinfo = str(xcustomroles) + ' custom roles'
                xstatus = SWARNING
            else :
                xinfo = None
                xstatus = SOK
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xroles), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xroles)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_samlsettings(self) :
        errorcount = 0
        inventory_name = 'access-control saml settings'
        xobject: str = OBJ_AC_SAML
        xstatus: int = SWARNING
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xcustomcount: int = 0
        xusercount: int = 0
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get users
            xusers = self.__internal_get_all_active_users(True)
            # Get SAML providers list
            xsamls = self.cxsca.get(self.cxsca.aclhost + '/samlidentityproviders')
            # Register to inventory
            for saml in xsamls :
                if saml['active'] :
                    xcounter += 1
                    provid = self.__internal_get_identity_provider_id( saml['name'], 'SAML' )
                    # Check users count
                    xusercount = 0
                    if len(xusers) > 0 :
                        xusercount = len( list( filter( lambda el: el['authenticationProviderId'] == provid, xusers) ) )
                    xinfo = 'issuer: ' + saml['issuer']
                    if xusercount > 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' users)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    elif xusercount == 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' user)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    else :
                        xinfo = xinfo + ' (no users)'
                        xstatus = SOK
                    self.__internal_write_config( [STATUS[xstatus], xobject, provid, saml['name'], None, None, xinfo ], False )
            # Register index
            xstatus = SOK
            xinfo = None
            if xcounter > 0 :
                xinfo = 'manual configuration required'
                if xcustomcount == 0 :
                    xstatus = SOK
                else:
                    xstatus = SWARNING
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_mastersettings(self) :
        errorcount = 0
        inventory_name = 'access-control master ac settings'
        xobject: str = OBJ_AC_MASTER_AC
        xstatus: int = SWARNING
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xcustomcount: int = 0
        xusercount: int = 0
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get users
            xusers = self.__internal_get_all_active_users(True)
            # Get SAML providers list
            xmaster = self.cxsca.get(self.cxsca.aclhost + '/primaryaccesscontrol')
            # Register to inventory
            if xmaster and xmaster['isActive'] :
                xcounter += 1
                provid = self.__internal_get_identity_provider_id( xmaster['name'], 'MasterAccessControl' )
                # Check users count
                xusercount = 0
                if len(xusers) > 0 :
                    xusercount = len( list( filter( lambda el: el['authenticationProviderId'] == provid, xusers) ) )
                xinfo = 'issuer: ' + xmaster['issuer']
                if xusercount > 1 :
                    xinfo = xinfo + ' (' + str(xusercount) + ' users)'
                    xstatus = SWARNING
                    xcustomcount += 1
                elif xusercount == 1 :
                    xinfo = xinfo + ' (' + str(xusercount) + ' user)'
                    xstatus = SWARNING
                    xcustomcount += 1
                else :
                    xinfo = xinfo + ' (no users)'
                    xstatus = SOK
                self.__internal_write_config( [STATUS[xstatus], xobject, provid, xmaster['name'], None, None, xinfo ], False )
            # Register index
            xstatus = SOK
            xinfo = None
            if xcounter > 0 :
                xinfo = 'manual configuration required'
                if xcustomcount == 0 :
                    xstatus = SOK
                else:
                    xstatus = SWARNING
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __internal_process_project_scan(self, scanid: str ) -> tuple[str, bool, str]:
        xscandata: dict = None
        xorigin: str = None
        xmanifest: bool = None
        xerror: str = None
        try :
            xscandata = self.cxsca.get( '/risk-management/scans/' + scanid )
            if xscandata :
                xorigin = xscandata.get('origin')
                xmanifest = xscandata.get('manifestFilesUploaded')
        except HTTPTimeout :
            xerror = 't/o'
        except Exception :
            xerror = 'n/p'
        return xorigin, xmanifest, xerror


    def __internal_process_project_scan_origin(self, scanorigin: str ) -> int :
        xstatus: int = SOK
        xscanorigins: list = self.cxcaches.cache(CACHE_SCAN_ORIGINS)
        if scanorigin :
            if not xscanorigins :
                xscanorigins = [ {"ORIGIN": scanorigin, "COUNT": 1, "STATUS": xstatus} ]
                self.cxcaches.putcache(CACHE_SCAN_ORIGINS, xscanorigins)
            else :
                xscanorigin = next( filter( lambda el: el["ORIGIN"] == scanorigin, xscanorigins), None )
                if xscanorigin :
                    xscanorigin["COUNT"] = int(xscanorigin["COUNT"]) + 1
                else :
                    xscanorigins.append( {"ORIGIN": scanorigin, "COUNT": 1, "STATUS": xstatus } )
        return xstatus


    def __internal_process_project_triages(self, scanid: str ) -> tuple[int, str]:
        # This one uses GraphQL
        xquery: str = '{"query":"query ($isExploitablePathEnabled: Boolean!, $scanId: UUID!, $where: VulnerabilityModelFilterInput) '
        xquery = xquery + '{ vulnerabilitiesRisksByScanId (isExploitablePathEnabled: $isExploitablePathEnabled, scanId: $scanId, where: $where) '
        xquery = xquery + '{ totalCount, risksLevelCounts { critical, high, medium, low, none, empty } } }","variables":{"isExploitablePathEnabled":true,'
        xquery = xquery + '"scanId":"' + scanid + '",'
        xquery = xquery + '"where":{"and":[{"or":[{"state":{"eq":"Confirmed"}},{"state":{"eq":"Urgent"}},{"state":{"eq":"NotExploitable"}},{"state":{"eq":"ProposedNotExploitable"}}]}]}}}'

        xscandata: dict = None
        xtriages: int = None
        xerror: str = None
        try :
            xscandata = self.cxsca.post( '/graphql/graphql', xquery )
            if xscandata :
                xscandata = xscandata.get('data')
                if xscandata :
                    xscandata = xscandata.get('vulnerabilitiesRisksByScanId')
                    if xscandata :
                        xtriages = xscandata.get('totalCount')
        except HTTPTimeout :
            xerror = 't/o'
        except Exception :
            xerror = 'n/p'
        return xtriages, xerror


    def __internal_process_project(self, project: dict ) :
        # Status and control
        xstatus: int = SOK
        xinfo: str = None

        # Caches
        xteamscache: list = self.cxcaches.cache(CACHE_TEAMS)

        # Auxiliary
        xauxlist: list = None
        xauxdict: dict = None
        xauxstrs: list[str] = None
        xauxstr: str = None

        # The variables holding the project output elements fields
        xprojid: int = project.get('id')
        xprojname: str = project.get('name')
        xcreatedon: str = self.__dateparse( project.get('createdOn') )
        xupdatedon: str = self.__dateparse( project.get('lastUpdate') )
        xexploitablepath: bool = project.get('enableExploitablePath')
        xlastsastscantime: int = project.get('lastSastScanTime')
        if not xlastsastscantime :
            xlastsastscantime = None
        xbranch: str = project.get('branch')
        xismanaged: bool = project.get('isManaged')
        xlastscan: str = project.get('latestScanId')

        # Process teams
        xteams: str = None
        xauxlist = project.get('assignedTeams')
        if xauxlist :
            xauxstrs = []
            for xteam in xauxlist :
                xauxstrs.append( xteam['teamPath'] )
                if xteamscache :
                    xauxdict = next( filter( lambda el: el['TEAM-NAME'] == xteam['teamPath'], xteamscache), None )
                    if xauxdict :
                        if not xauxdict['PROJ-USING'] :
                            xauxdict['PROJ-USING'] = 1
                        else :
                            xauxdict['PROJ-USING'] = xauxdict['PROJ-USING'] + 1
            if len(xauxstrs) > 0 :
                xteams = SPLITTER.join(xauxstrs)

        # Process tags
        xtagcount: int = None
        xauxlist = project.get('tags')
        if xauxlist and len(xauxlist) > 0:
            xtagcount = len(xauxlist)

        # Scan info
        xorigin: str = None
        xmanifest: bool = None
        xtriages: int = None
        # Risk report
        xriskreportid: str = None
        xriskreportcreated: str = None
        xriskreportupdated: str = None
        xdirectpackages: int = None
        xtotalpackages: int = None
        xoutdatedpackages: int = None
        xcritical: int = None
        xhigh: int = None
        xmedium: int = None
        xlow: int = None
        xignored: int = None
        xlastscanned: str = None
        xseverity: str = None
        xviolated: bool = None
        xisprivate: bool = None
        if not self.__noscandata :

            # Process risk report
            xriskreport: dict = project.get('riskReportSummary')
            if xriskreport :
                xriskreportid = xriskreport.get('id')
                xriskreportcreated = self.__dateparse( xriskreport.get('riskReportCreatedOn') )
                xriskreportupdated = self.__dateparse( xriskreport.get('riskReportLastUpdate') )
                xdirectpackages = xriskreport.get('directPackages')
                xtotalpackages = xriskreport.get('totalPackages')
                xoutdatedpackages = xriskreport.get('totalOutdatedPackages')
                xcritical = xriskreport.get('criticalVulnerabilityCount')
                if not xcritical :
                    xcritical = 0
                xhigh = xriskreport.get('highVulnerabilityCount')
                xmedium = xriskreport.get('mediumVulnerabilityCount')
                xlow = xriskreport.get('lowVulnerabilityCount')
                xignored = xriskreport.get('ignoredVulnerabilityCount')
                xlastscanned = self.__dateparse( xriskreport.get('lastScanned') )
                xseverity = xriskreport.get('severity')
                xviolated = xriskreport.get('isViolated')
                xisprivate = xriskreport.get('isPrivatePackage')

            # Resolve origin
            if xlastscan :
                xorigin, xmanifest, xauxstr = self.__internal_process_project_scan(xlastscan)
                if xauxstr :
                    xorigin = xauxstr

            # Get triages count
            if xlastscan and not self.__notriages :
                xtriages, xauxstr = self.__internal_process_project_triages(xlastscan)
                if xauxstr :
                    xtriages = xauxstr

        # Record scan origin
        if xorigin :
            self.__internal_process_project_scan_origin(xorigin)

        # Write it to csv
        if not self.__projshandler :
            filename = self.__datapath + os.sep + OUT_PROJECTS
            self.__projshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__projswriter = csv.writer(self.__projshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__projswriter.writerow(CSV_PROJECTS)
        # Write it
        self.__projswriter.writerow( [ STATUS[xstatus], xprojid, xprojname, xcreatedon, xupdatedon,
                                    xexploitablepath, xlastsastscantime, xbranch, xismanaged,
                                    xlastscan, xtagcount, xteams,
                                    xriskreportid, xriskreportcreated, xriskreportupdated,
                                    xdirectpackages, xtotalpackages, xoutdatedpackages,
                                    xcritical, xhigh, xmedium, xlow, xignored, xtriages,
                                    xorigin, xmanifest, xlastscanned, xseverity, xviolated, xisprivate,
                                    xinfo
                                    ] )


    def __inventory_projects(self) :
        errorcount = 0
        inventory_name = 'projects'
        xobject: str = OBJ_PROJECTS
        xstatus: int = SOK
        xinfo: str = None
        xcounter: int = 0
        xnotfoundcount: int = 0
        xprojectcount: int = 0
        xskip: int = 0
        xstarted = CxDatetime.now()
        if self.__noscandata :
            cxlogger.info( 'Processing ' + inventory_name + ' without scan data' )
        else :
            cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Count projects
            xprojectsaggregated: dict = self.cxsca.get('/risk-management/projects/aggregated-data')
            if xprojectsaggregated :
                xprojectcount = xprojectsaggregated.get('totalProjects')
            cxlogger.info('Counted ' + str(xprojectcount) + ' total projects (unfiltered) ... ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

            if self.__projectfilter and len(self.__projectfilter) > 0 :
                xprjstarted = CxDatetime.now()
                for xfilter in self.__projectfilter :
                    if self.__noscandata :
                        xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$filter=id eq ' + xfilter + '&$expand=tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=1&$skip=0' )
                    else :
                        xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$filter=id eq ' + xfilter + '&$expand=riskReportSummary,tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=1&$skip=0' )
                    if len(xprojects) > 0 :
                        self.__internal_process_project(xprojects[0])
                        xcounter += 1
                    else :
                        xnotfoundcount += 1
                    if (((xcounter + xnotfoundcount) % 100) == 0) or ((xcounter + xnotfoundcount) == len(self.__projectfilter)) :
                        # Log page time
                        cxlogger.info('Processed ' + str(xcounter + xnotfoundcount) + ' of ' + str(xprojectcount) + ' filtered projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                        xprjstarted = CxDatetime.now()
            else :
                # Non filtered
                xprjstarted = CxDatetime.now()
                if self.__noscandata :
                    xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$expand=tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=100&$skip=' + str(xskip) )
                else :
                    xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$expand=riskReportSummary,tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=100&$skip=' + str(xskip) )
                while len(xprojects) > 0 :
                    for xproject in xprojects :
                        self.__internal_process_project(xproject)
                        xcounter += 1
                    # Log page time
                    if self.__projectfilter :
                        cxlogger.info('Processed ' + str(xcounter) + ' of ' + str(xprojectcount) + ' filtered projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                    else :
                        cxlogger.info('Processed ' + str(xcounter) + ' of ' + str(xprojectcount) + ' projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                    xprjstarted = CxDatetime.now()
                    if len(xprojects) < 100 :
                        xprojects = []
                    else :
                        xskip += 100
                        if self.__noscandata :
                            xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$expand=tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=100&$skip=' + str(xskip) )
                        else :
                            xprojects = self.cxsca.get('/risk-management/projectsriskreportsummary?$expand=riskReportSummary,tags,assignedTeams($filter=isDirectlyAssigned eq true)&$top=100&$skip=' + str(xskip) )

            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsca.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_process_teams_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_TEAMS)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'teams counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_ACTEAMS
                tempfile = self.__datapath + os.sep + '_' + OUT_ACTEAMS
                auxfile = self.__datapath + os.sep + '__' + OUT_ACTEAMS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['TEAM-ID'] == xobject['TEAM-ID'] and el['TEAM-NAME'] == xobject['TEAM-NAME'], xcache ), None )
                    if xcacheobj and ( xcacheobj['PROJ-USING'] or xcacheobj['PROJ-USING'] ):
                        xcount += 1
                        xobject['PROJ-USING'] = xcacheobj['PROJ-USING']
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xobject)
                    # Go for the next
                    xobject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(datafile, auxfile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(tempfile, datafile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process teams counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_TEAMS)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_origins(self) :
        errorcount: int = 0
        xcacheorigins = self.cxcaches.cache(CACHE_SCAN_ORIGINS)
        # Have we anything to process ?
        if not ( xcacheorigins and len(xcacheorigins) > 0 ) :
            return errorcount

        xcount: int = 0
        inventory_name = 'scan origins'
        xsummary: list[dict] = None
        xsummaryfile = self.__datapath + os.sep + OUT_SUMMARY
        xconfig: list[dict] = None
        xconfigfile = self.__datapath + os.sep + OUT_CONFIG
        xmaxstatus: int = SOK
        xstatus: int = SOK
        xdata: dict = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )

        try :
            xsummary = self.cxcsv.csvload( xsummaryfile )

            # Go for scan origins
            if ( xcacheorigins and len(xcacheorigins) > 0 ) :
                # Update config file
                xconfig = self.cxcsv.csvload( xconfigfile )
                for origin in xcacheorigins :
                    xstatus = origin['STATUS']
                    if xstatus > xmaxstatus :
                        xmaxstatus = xstatus
                    xdata = { 'STATUS': STATUS[xstatus],
                             'OBJ-TYPE': OBJ_SCAN_ORIGINS,
                             'OBJ-ID': None,
                             'OBJ-NAME': origin['ORIGIN'],
                             'OBJ-REF': None,
                             'PROJ-USING': origin['COUNT'],
                             'NOTES': None
                             }

                    xconfig.append(xdata)
                    xcount += 1
                # Summary scan origins counts
                xdata = { 'STATUS': STATUS[xstatus],
                         'OBJ-TYPE': OBJ_SCAN_ORIGINS,
                         'OBJ-COUNT': len(xcacheorigins),
                         'NOTES': 'scan origins'
                         }
                xsummary.append(xdata)

        except Exception as e :
            errorcount += 1
            cxlogger.exception( e, level = DEBUG )
            cxlogger.error('failed to process scan origins')
        finally :
            if xsummary :
                self.cxcsv.csvsave( xsummaryfile, xsummary )
            if xconfig :
                self.cxcsv.csvsave( xconfigfile, xconfig )

        # Clear unneeded cache
        self.cxcaches.uncache(CACHE_SCAN_ORIGINS)
        # Close
        cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def execute(self) -> int :
        errorcount: int = 0
        xstarted = CxDatetime.now()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'SCA inventory start, ' + CxDatetime.nowastext() )
        cxlogger.info( '=============================================================================' )

        # Describe options
        if self.__noiam or self.__usersfull or self.__noscandata or self.__notriages or self.__projectfilter :
            cxlogger.info( 'Execution options:' )
            if self.__noiam :
                cxlogger.info( "> options.no-iam" )
            if self.__usersfull :
                cxlogger.info( "> options.detailed-users" )
            if self.__noscandata :
                cxlogger.info( "> options.no-scans" )
            if self.__notriages :
                cxlogger.info( "> options.no-triages" )
            if self.__projectfilter :
                # Throws exception
                try :
                    xfilterdata: any = CxParamFilters.processfilter(filter = self.__projectfilter, numerics = False, guids = False, odatanum = False)
                    if xfilterdata :
                        if isinstance(xfilterdata, list) :
                            self.__projectfilter = xfilterdata
                            if len(xfilterdata) == 1 :
                                cxlogger.info( "> options.projects-filter: " + str(xfilterdata[0]) )
                            else :
                                cxlogger.info( "> options.projects-filter: " + str(len(xfilterdata)) + " projects" )
                        else :
                            self.__projectfilter = [xfilterdata]
                            cxlogger.info( "> options.projects-filter: " + str(xfilterdata) )
                    else :
                        cxlogger.error( "> options.projects-filter: invalid expression" )
                        self.__projectfilter = None
                        errorcount += 1
                except Exception :
                    cxlogger.error( "> options.projects-filter: invalid expression" )
                    self.__projectfilter = None
                    errorcount += 1
            cxlogger.info( '=============================================================================' )

        # Connect to CXSCA
        if errorcount == 0 :
            if not self.__initconnection() :
                errorcount += 1

            # Initialize output folders and files
            elif self.__preparedatafiles() :
                try :
                    # Process SCA tenant configurations
                    errorcount += self.__inventory_scainstance()
                    # Process SCA ac data
                    errorcount += self.__inventory_ac_users()
                    errorcount += self.__inventory_ac_teams()
                    errorcount += self.__inventory_ac_roles()
                    errorcount += self.__inventory_ac_samlsettings()
                    errorcount += self.__inventory_ac_mastersettings()
                    # Dispose of caches we don't need anymore
                    self.cxcaches.uncache(CACHE_AC_USERS)
                    self.cxcaches.uncache(CACHE_AC_TEAMS)
                    # Process projects
                    errorcount += self.__inventory_projects()
                    # Close the files
                    self.__closedatafiles()
                    # Post-process object counters
                    errorcount += self.__inventory_process_teams_counters()
                    # Post-process origins
                    errorcount += self.__inventory_process_origins()

                except Exception as e :
                    errorcount += 1
                    cxlogger.exception(e)

            else :
                errorcount += 1

        # Ensure data files closure
        self.__closedatafiles()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'SCA inventory end, ' + CxDatetime.nowastext() )
        if errorcount > 0 :
            cxlogger.warning( 'Found ' + str(errorcount) + ' errors, check the logs' )
        cxlogger.info( 'Duration ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        cxlogger.info( '=============================================================================' )

        return errorcount
