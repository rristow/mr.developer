from mr.developer import common
import getpass
import os
import subprocess
import sys

logger = common.logger


class TFError(common.WCError):
    pass


class TFAuthorizationError(TFError):
    pass


class TFParserError(TFError):
    pass


# --- Standard output 'expressions' of tf client ---

# The item_spec (folder) is not mapped to the server
STDOUT_EXP_UNMAPPED_PROPS = 'must be a server item'
STDOUT_EXP_UNMAPPED_STATUS = 'There is no working folder mapping'
# No Authentication provided (no argument: profile or user)
STDOUT_EXP_AUTHENTICATION_NOT_PROVIDED = \
        'Authentication credentials were not explicitly provided'
# Wrong password
STDOUT_EXP_ACCESS_DENIED = 'Access denied'
# No pendings returned from 'status' command
STDOUT_EXP_STATUS_OK = 'There are no matching pending changes'
# No updates returned from 'get -preview' command
STDOUT_EXP_GET_PREVIEW_OK = "All files up to date"


class TFWorkingCopy(common.BaseWorkingCopy):
    _tf_properties_cache = {}
    _tf_auth_cache = {}
    _executable_names = ['tf.cmd', 'tf']

    def __init__(self, *args, **kwargs):
        common.BaseWorkingCopy.__init__(self, *args, **kwargs)
        self.tf_executable = common.which(*self._executable_names)
        if self.tf_executable is None:
            logger.error("Cannot find tf executable in PATH")
            sys.exit(1)

    def _tf_append_argument(self, args, arg_ids, pos=2):
        """ Append (if exists) all arguments in the "arg_ids" list
            into args.
        """
        for arg_id in arg_ids:
            if self.source.get(arg_id, ''):
                args.insert(pos, '-%s:%s' % (arg_id, self.source[arg_id]))

    def _tf_auth_get(self, workspace):
        """ Get the credentials from local/temporary cache.
        """
        for workspace_cache in self._tf_auth_cache:
            if  workspace_cache == workspace:
                return self._tf_auth_cache[workspace]

    def _tf_communicate(self, args, **kwargs):
        """ Execute the process (tf command) adding the arguments:
              -noprompt
              -username (if already in cache)
        """
        workspace = self.source.get('workspace', '')
        auth = self._tf_auth_get(workspace)
        if auth is not None:
            args[2:2] = ["-login:%s,%s" %
                         (auth.get('user', ''), auth.get('passwd', ''))]
        args[2:2] = ["-noprompt"]

        ret = ' '.join(args)
        logger.debug("    >> %s",
                     ret.replace(auth and auth.get('passwd', '') or 'nothing',
                                 '<hidden>'))

        cmd = subprocess.Popen(args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = cmd.communicate()
        if cmd.returncode != 0:
            lines = stderr.strip().split('\n')
            for line in lines:
                for auth_error in [STDOUT_EXP_AUTHENTICATION_NOT_PROVIDED,
                                   STDOUT_EXP_ACCESS_DENIED]:
                    if auth_error in line:
                        raise TFAuthorizationError(stderr.strip())
        return stdout, stderr, cmd.returncode

    def _tf_error_wrapper(self, f, **kwargs):
        """ Execute the function "f". If a "TFAuthorizationError" occurs
            than ask for the password an try again.
        """
        count = 4
        usr_default = ''
        while count:
            count = count - 1
            try:
                return f(**kwargs)
            except TFAuthorizationError:
                workspace = self.source.get('workspace', '')
                before = self._tf_auth_cache.get(workspace)
                common.output_lock.acquire()
                common.input_lock.acquire()
                after = self._tf_auth_cache.get(workspace)
                if before != after:
                    count = count + 1
                    common.input_lock.release()
                    common.output_lock.release()
                    continue
                try:
                    print "Authorization needed for '%s' at '%s'" % (self.source['name'], self.source['url'])
                    #Try to get the default username from sources
                    #(login argument)
                    if not usr_default and self.source.get('login', ''):
                        usr_default = self.source['login'].split(",")[0]
                    if usr_default:
                        user = raw_input("Username (DOMAIN\username or username@domain) [%s]: " % usr_default)
                        if not user:
                            user = usr_default
                    else:
                        user = raw_input("Username (DOMAIN\username or username@domain):")
                    if user:
                        usr_default = user
                    else:
                        logger.warning(
                            "Authentication credentials were not provided")
                        raise
                    passwd = getpass.getpass("Password: ")
                    self._tf_auth_cache[workspace] = dict(
                        user=user,
                        passwd=passwd)
                finally:
                    common.input_lock.release()
                    common.output_lock.release()

################################################################################

    def _tf_workfold_map(self, **kwargs):
        """ Map a local folder with a server folder.
        """
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        # Mapping the local folder
        args = [self.tf_executable, "workfold", url, path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf workfold' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def tf_workfold_map(self, **kwargs):
        """ Mapp a local folder.
        """
        return self._tf_error_wrapper(self._tf_workfold_map, **kwargs)

    def _tf_workfold_unmap(self, **kwargs):
        """ Unmapp a local folder.
        """
        name = self.source['name']
        path = self.source['path']

        # Mapping the local folder
        args = [self.tf_executable, "workfold", "-unmap", path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf workfold -unmap' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def tf_workfold_unmap(self, **kwargs):
        """ Mapp a local folder.
        """
        return self._tf_error_wrapper(self._tf_workfold_unmap, **kwargs)

    def _tf_parse_properties(self, str):
        """ parse the result of the command 'properties'.
        Return dictionaries with the 'local' and 'server' properties. e.g.

        Examples::
        >>> self._tf_parse_properties("\
           Local information:\
               Local path:  /prod_test \
           Server information:\
               Server path:   $/REP/pro_test ")
        ({'Local path': '/prod_test'},   {'Server path': '$/REP/pro_test'})
        """
        local = {}
        server = {}
        if str.startswith('No items match'):
            return local, server
        if 'Server information:' in str:
            locstr, servstr = str.split('Server information:')
            if 'Local information:' in locstr:
                locstr = locstr.split('Local information:')[1]
                for info in locstr.split("\n"):
                    if ":" in info:
                        str = info.split(":")
                        local[str[0].strip().lower()] = str[1].strip()

                for info in servstr.split("\n"):
                    if ":" in info:
                        str = info.split(":")
                        server[str[0].strip().lower()] = str[1].strip()
                return local, server
            else:
                raise TFParserError("Expected 'Local information:'")
        else:
            raise TFParserError("Expected 'Server information:'")

    def _tf_properties(self, **kwargs):
        """
        Return the information from mapping/server.

        tf syntax:
        tf properties [/collection:TeamProjectCollectionUrl] [/recursive]
        [/login:username,[password]] itemspec [/version:versionspec]
        [/workspace]

        Return:

        """
        name = self.source['name']
        if name in self._tf_properties_cache:
            return True, self._tf_properties_cache[name]
        path = self.source['path']

        args = [self.tf_executable, "properties", path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        result = {}
        if returncode != 0:
            # The is no mappings for this folder
            if STDOUT_EXP_UNMAPPED_PROPS in stdout + stderr:
                return True, result
            else:
                raise TFError("'tf properties' command for '%s' failed.\n%s" %
                              (name, stderr))
        local, server = self._tf_parse_properties(stdout)

        if server:
            if local.get('server path'):
                result['url'] = local['server path']
                self._tf_properties_cache[name] = result
                return True, result
            else:
                raise TFParserError(
                    "Server information: 'Server path' not found in tf output")
        else:
            return False,"It was not possible to get the properties from destination ('tf properties')"

    def tf_properties(self, **kwargs):
        """
        """
        return self._tf_error_wrapper(self._tf_properties, **kwargs)

    def _tf_get(self, **kwargs):
        """ Retrieves a copy from the server.
        tf syntax:
        tf get [itemspec] [/version:versionspec] [/all] [/overwrite] [/force]
        [/preview] [/recursive] [/remap] [/noprompt]
        [/login:username,[password]]
        """
        name = self.source['name']
        path = self.source['path']

        args = [self.tf_executable, "get", "-recursive", "-all", path]
        self._tf_append_argument(args, ['profile', 'login', 'version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def _tf_get_force(self, **kwargs):
        """ Retrieves a copy from the server.
        tf syntax:
        tf get [itemspec] [/version:versionspec] [/all] [/overwrite] [/force]
        [/preview] [/recursive] [/remap] [/noprompt]
        [/login:username,[password]]
        """
        name = self.source['name']
        path = self.source['path']

        args = [self.tf_executable, "get", "-force", "-recursive", "-all", path]
        self._tf_append_argument(args, ['profile', 'login', 'version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get' (force) command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def tf_get_force(self, **kwargs):
        name = self.source['name']
        self.output((logger.info,
            "Get (force) '%s' from Microsoft Team Foundation Server." % name))
        return self._tf_error_wrapper(self._tf_get_force, **kwargs)

    def tf_switch(self, **kwargs):
        """ Remove the mapping with the local folder and map/update it again
        in the new location.
        """
        logger.debug("  Executing 'switch' (tf workfold 'unmap' and 'map' again).")
        self.tf_workfold_unmap(**kwargs)
        return self.tf_workfold_map(**kwargs)


    def tf_get(self, **kwargs):
        name = self.source['name']
        self.output((logger.info,
            "Get '%s' from Microsoft Team Foundation Server." % name))
        return self._tf_error_wrapper(self._tf_get, **kwargs)

    def _tf_status_clean(self, **kwargs):
        """
        Check/preview changes from local folder.
        """
        name = self.source['name']
        path = self.source['path']

        if not os.path.exists(path):
            return 'clean'

        args = [self.tf_executable, "status", "-recursive", path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)

        if returncode != 0:
            # The is no mappings for this folder
            if STDOUT_EXP_UNMAPPED_STATUS in stdout + stderr:
                return False, stdout
            else:
                raise TFError("'tf status' command for '%s' failed.\n%s" %
                              (name, stderr))
        return STDOUT_EXP_STATUS_OK in stdout, stdout

################################################################################

    def checkout(self, **kwargs):
        logger.debug("Executing checkout.")
        name = self.source['name']
        path = self.source['path']
        props_ret, props = self.tf_properties(**kwargs)
        if props_ret:
            if props.get('url') == self.source['url']:
                toupdate = self.should_update(**kwargs)
                if toupdate:
                    self.tf_get(**kwargs)
                else:
                    self.output(
                        (logger.info,
                         "Skipped checkout of existing package '%s'." % name))
                    return None
            else:
                self.tf_switch(**kwargs)
                self.tf_get_force(**kwargs)
        else:
            self.tf_workfold_map()
            self.tf_get_force(**kwargs)

    def matches(self, **kwargs):
        """ Check if the mapping matches 
        """
        logger.debug("%s: Executing matches."%(self.source['name']))
        props_ret, props = self._tf_error_wrapper(self._tf_properties, **kwargs)
        if props_ret:
            ret = props.get('url') == self.source['url']
            logger.debug("  %s: The actual mapping '%s' do not match with '%s'"%
                         (self.source['name'], props.get('url'), 
                          self.source['url']))
        else:
            # No properties (folder is not mapped)
            logger.debug("  %s: It was not possible to check the properties."%
                         (self.source['name']))
            ret = False
        return ret

    def status(self, **kwargs):
        logger.debug("Executing status.")
        clean, stdout = self._tf_error_wrapper(self._tf_status_clean, **kwargs)

        if clean:
            status = 'clean'
        else:
            status = 'dirty'
        logger.debug("status return: %s.", status)
        if kwargs.get('verbose', False):
            return status, stdout
        else:
            return status

    def update(self, **kwargs):
        logger.debug("Executing update")
        force = kwargs.get('force', False)
        #Switch
        if not self.matches():
            status = self.status()
            if force or status == 'clean':
                return self._tf_error_wrapper(self.tf_switch, **kwargs)
            else:
                raise TFError("It was not possible to switch '%s' to '%s' "
                              "because the destination is dirty.")
        #Update
        return self.tf_get(**kwargs)

common.workingcopytypes['tf'] = TFWorkingCopy
