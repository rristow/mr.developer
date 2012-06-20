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

    _executable_names = ['tf', 'tf.cmd']

    def __init__(self, *args, **kwargs):
        common.BaseWorkingCopy.__init__(self, *args, **kwargs)
        self.tf_executable = common.which(*self._executable_names)
        if self.tf_executable is None:
            logger.error("Cannot find tf executable in PATH")
            sys.exit(1)

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

    def _tf_auth_get(self, workspace):
        """ Get the credentials from local/temporary cache.
        """
        for workspace_cache in self._tf_auth_cache:
            if  workspace_cache == workspace:
                return self._tf_auth_cache[workspace]

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

    def _tf_append_argument(self, args, arg_ids, pos=2):
        """ Append (if exists) all arguments in the "arg_ids" list
            into args.
        """
        for arg_id in arg_ids:
            if self.source.get(arg_id, ''):
                args.insert(pos, '-%s:%s' % (arg_id, self.source[arg_id]))

    def _tf_workfold(self, **kwargs):
        """ Map a local folder with a server folder.
        """
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        # Mapping the local folder
        Vargs = [self.tf_executable, "workfold", url, path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf workfold' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def _tf_checkout(self, **kwargs):
        """ Map a local folder and get from server.
        """
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']
        logger.debug("  Checking informations (tf properties) from '%s'"
                                 % path)
        info = self._tf_properties(**kwargs)

        # Verify the mapping
        if not info.get('url'):
            logger.debug("  Mapping (tf workfold) '%s' with the repository"
                                     % name)
            self._tf_workfold(**kwargs)
        # remote and local paths are already mapped
        elif info.get('url') == 'null':
            pass
        # remote and local paths are already mapped
        # but to a different location
        elif info['url'] != url:
                raise TFError("The path '%s' is already mapped to '%s'." %
                              (path, info['url']))

        # Get content from server
        # Mapping the local folder
        args = [self.tf_executable, "get", "-recursive", path]
        self._tf_append_argument(args, ['profile', 'login', 'version'])
        logger.debug("  Synchronizing (tf get) with the repository")
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

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
            return self._tf_properties_cache[name]
        path = self.source['path']

        args = [self.tf_executable, "properties", path]
        self._tf_append_argument(args, ['workspace', 'profile', 'login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        result = {}
        if returncode != 0:
            # The is no mappings for this folder
            if STDOUT_EXP_UNMAPPED_PROPS in stdout + stderr:
                return result
            else:
                raise TFError("'tf properties' command for '%s' failed.\n%s" %
                              (name, stderr))
        local, server = self._tf_parse_properties(stdout)

        if local:
            if local.get('server path'):
                result['url'] = local['server path']
            else:
                raise TFParserError(
                    "Local information: 'Server path' not found in tf output")
            self._tf_properties_cache[name] = result
        return result

    def _tf_update(self, **kwargs):
        """ Retrieves a copy from the server.
        tf syntax:
        tf get [itemspec] [/version:versionspec] [/all] [/overwrite] [/force]
        [/preview] [/recursive] [/remap] [/noprompt]
        [/login:username,[password]]
        """
        name = self.source['name']
        path = self.source['path']

        args = [self.tf_executable, "get", "-recursive", path]
        self._tf_append_argument(args, ['profile', 'login', 'version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get' command for '%s' failed.\n%s" %
                          (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def tf_checkout(self, **kwargs):
        name = self.source['name']
        path = self.source['path']
        if os.path.exists(path):
            self.output((logger.info,
                         "Skipped checkout of existing package '%s'." % name))
            return
        self.output((logger.info,
            "Checked out '%s' from Microsoft Team Foundation Server." % name))
        return self._tf_error_wrapper(self._tf_checkout, **kwargs)

    def tf_switch(self, **kwargs):
        """ Remove the mapping with the local folder and map/update it again
        in the new location.
        """
        logger.debug("  Executing 'switch' (tf workfold 'unmap' and 'map' again).")
        self._tf_workfold_unmap(**kwargs)
        return self._tf_checkout(**kwargs)

    def tf_update(self, **kwargs):
        name = self.source['name']
        self.output((logger.info,
            "Updated '%s' from Microsoft Team Foundation Server." % name))
        return self._tf_error_wrapper(self._tf_update, **kwargs)

    def checkout(self, **kwargs):
        logger.debug("Executing checkout.")
        name = self.source['name']
        path = self.source['path']
        update = self.should_update(**kwargs)
        if os.path.exists(path):
            matches = self.matches()
            if matches:
                if update:
                    self.update(**kwargs)
                else:
                    self.output(
                        (logger.info,
                         "Skipped checkout of existing package '%s'." % name))
            else:
                if self.status() == 'clean':
                    return self.tf_switch(**kwargs)
                else:
                    raise TFError(
                        ("Can't switch package '%s' to '%s' because "
                         "destination is dirty.") %
                        (name, self.source['url']))
        else:
            return self._tf_error_wrapper(self.tf_checkout, **kwargs)

    def _tf_preview_clean(self, **kwargs):
        """
        Check/preview changes from local folder.
        """
        name = self.source['name']
        path = self.source['path']

        # get from server
        args = [self.tf_executable, "get", "-preview", "-recursive", path]
        self._tf_append_argument(args, ['profile', 'login', 'version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get -preview' command for '%s' failed.\n%s" %
                          (name, stderr))
        return STDOUT_EXP_GET_PREVIEW_OK in stdout

    def matches(self, **kwargs):
        logger.debug("Executing matches.")
        props = self._tf_error_wrapper(self._tf_properties, **kwargs)
        if props:
            preview_clean = self._tf_error_wrapper(self._tf_preview_clean,
                                                   **kwargs)
            logger.debug(preview_clean and "  The 'URL' matches with repository (checked with: tf properties)" or "  The 'URL' do NOT match with repository (checked with: tf properties)")
            logger.debug(preview_clean and "  The files are updated (checked with: tf get -preview)" or "  The files are NOT updated (checked with: tf get -preview)")
            ret = props.get('url') == self.source['url'] and preview_clean
        else:
            # No properties (folder is not mapped)
            logger.debug("  It was not possible to check the properties. (tf properties)")
            ret = False
        logger.debug("matches return: '%s'" % ret)
        return ret

    def _tf_status_clean(self, **kwargs):
        """
        Check/preview changes from local folder.
        """
        name = self.source['name']
        path = self.source['path']

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
        status = self.status()
        #Switch
        if not self.matches():
            if force or status == 'clean':
                return self._tf_error_wrapper(self.tf_switch, **kwargs)
            else:
                raise TFError("It was not possibel to switch '%s' to the new "
                              "location. There are uncommited changes")
        #Update
        return self.tf_update(**kwargs)

common.workingcopytypes['tf'] = TFWorkingCopy
