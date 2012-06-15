from mr.developer import common
import platform

try:
    import xml.etree.ElementTree as etree
except ImportError:
    import elementtree.ElementTree as etree
import getpass
import os
import re
import subprocess
import sys

logger = common.logger

if 'Windows' in platform.system() or 'Microsoft' in platform.system():
    TF = 'tf.cmd'
else:
    TF = 'tf'

class TFError(common.WCError):
    pass

class TFAuthorizationError(TFError):
    pass

class TFParserError(TFError):
    pass

# --- Standard output 'expressions' of tf client ---

# The item_spec (folder) is not mapped to the server
STDOUT_EXP_UNMAPPED = 'must be a server item'
# No Authentication provided (no argument: profile or user)
STDOUT_EXP_AUTHENTICATION_NOT_PROVIDED = 'Authentication credentials were not explicitly provided'
# Wrong password
STDOUT_EXP_ACCESS_DENIED = 'Access denied'
# No pendings returned from 'status' command
STDOUT_EXP_STATUS_OK = 'There are no matching pending changes'
# No updates returned from 'get -preview' command
STDOUT_EXP_GET_PREVIEW_OK = "All files up to date"

class TFWorkingCopy(common.BaseWorkingCopy):
    _tf_properties_cache = {}
    _tf_auth_cache = {}

    def __init__(self, *args, **kwargs):
        common.BaseWorkingCopy.__init__(self, *args, **kwargs)
        self._tf_check_executable()

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
        
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_parse_properties '
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

    def _tf_check_executable(self):
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_check_executable '
        try:
            cmd = subprocess.Popen([TF, "-h"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        except OSError, e:
            if getattr(e, 'errno', None) == 2:
                logger.error("Couldn't find '%s' executable on your PATH."%TF)
                sys.exit(1)
            raise

    def _tf_auth_get(self, workspace):
        """ Get the credentials from local/temporary cache.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_auth_get '
        for workspace_cache in self._tf_auth_cache:
            if  workspace_cache == workspace:
                return self._tf_auth_cache[workspace]

    def _tf_error_wrapper(self, f, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_error_wrapper '
        count = 4
        while count:
            count = count - 1
            try:
                return f(**kwargs)
            except TFAuthorizationError, e:
                lines = e.args[0].split('\n')
                workspace = self.source.get('workspace', '')
                #TODO: after, before???
                before = self._tf_auth_cache.get(workspace)
                common.output_lock.acquire()
                common.input_lock.acquire()
                after = self._tf_auth_cache.get(workspace)
                if before != after:
                    count = count + 1
                    common.input_lock.release()
                    common.output_lock.release()
                    continue
                print "Authorization needed for '%s' at '%s'" % (self.source['name'], self.source['url'])
                user = raw_input("Username (DOMAIN\username or username@domain): ")
                if not user:
                    #todo: remove this 
		    user='rodrigo.ristow@adm.ds.fhnw.ch'
                    #raise TFError("Authentication credentials were not provided")
                passwd = getpass.getpass("Password: ")
                self._tf_auth_cache[workspace] = dict(
                    user=user,
                    passwd=passwd,
                )
                common.input_lock.release()
                common.output_lock.release()

    def _tf_workfold_unmap(self, **kwargs):
        """ Unmapp a local folder.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_workfold_unmap '
        name = self.source['name']
        path = self.source['path']

        # Mapping the local folder
        args = [TF, "workfold", "-unmap", path]
        self._tf_append_argument(args,['workspace','profile','login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf workfold -unmap' for '%s' failed.\n%s" % (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def _tf_append_argument(self, args, arg_ids, pos=2):
	""" Append (if exists) all arguments in the "arg_ids" list 
            into args.
        """
        for arg_id in arg_ids:
            if self.source.get(arg_id, ''):
                args.insert(pos, '-%s:%s' % (arg_id,self.source[arg_id]))

    def _tf_workfold(self, **kwargs):
        """ Mapp a local folder.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_workfold '
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        # Mapping the local folder
        args = [TF, "workfold", url, path]
        self._tf_append_argument(args,['workspace','profile','login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf workfold' for '%s' failed.\n%s" % (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def _tf_checkout(self, **kwargs):
        """ Mapp a local folder and get from server.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_checkout '
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']
        info = self._tf_properties(**kwargs)

        # Verify the mapping
        if info.get('url',''):
            #There is a mapping already
            if info['url'] != url:
                raise TFError("The path '%s' is already mapped to '%s'."%(path,info['url']))
        else:
            self._tf_workfold(**kwargs)

        # Get content from server
        # Mapping the local folder
        args = [TF, "get", "-recursive", path]
        self._tf_append_argument(args,['profile','login','version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get' for '%s' failed.\n%s" % (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def _tf_communicate(self, args, **kwargs):
        """ Execute the process (tf command) adding the arguments:
              -noprompt
              -username (if already in cache)
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_communicate '
        workspace = self.source.get('workspace', '')
        auth = self._tf_auth_get(workspace)
        if auth is not None:
            args[2:2] = ["-login:%s,%s"%(auth.get('user',''),auth.get('passwd',''))]
#        accept_invalid_cert = self._tf_accept_invalid_cert_get(url)
#        if 'always_accept_server_certificate' in kwargs:
#            if kwargs['always_accept_server_certificate']:
#                accept_invalid_cert = True
#        if accept_invalid_cert is True:
#            args[2:2] = ["--trust-server-cert"]
#        elif accept_invalid_cert is False:
#            raise TFCertificateRejectedError("Server certificate rejected by user.")
#        args[2:2] = ["--no-auth-cache"]
#        interactive_args = args[:]
        args[2:2] = ["-noprompt"]

        #TODO: Remove this
        ret = ' '.join(args)
        print "(DEBUG  TF)  >> ",ret.replace(auth and auth.get('passwd','') or 'nothing','<hidden>')
        cmd = subprocess.Popen(args,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = cmd.communicate()
        if cmd.returncode != 0:
            lines = stderr.strip().split('\n')
            for line in lines:
                for auth_error in [STDOUT_EXP_AUTHENTICATION_NOT_PROVIDED, STDOUT_EXP_ACCESS_DENIED]:
                    if auth_error in line:
                        raise TFAuthorizationError(stderr.strip())
        return stdout, stderr, cmd.returncode

    def _tf_properties(self, **kwargs):
        """
        Return the information from mapping/server.

        tf syntax:
        tf properties [/collection:TeamProjectCollectionUrl] [/recursive]
        [/login:username,[password]] itemspec [/version:versionspec] [/workspace]
        
        Return:

        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_properties '
        name = self.source['name']
        if name in self._tf_properties_cache:
            return self._tf_properties_cache[name]
        path = self.source['path']
        
        args = [TF, "properties", path]        
        self._tf_append_argument(args,['workspace','profile','login'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        result = {}
        if returncode != 0:
            # The is no mappings for this folder
            if STDOUT_EXP_UNMAPPED in stdout+stderr:
                return result
            else:
                raise TFError("'tf properties' command for '%s' failed.\n%s" % (name, stderr))
        local, server = self._tf_parse_properties(stdout)
       
        if local:
            if local.get('server path'):
                result['url'] = local['server path']
            else:
                raise TFParserError("Local information: 'Server path' not found in tf output")
            self._tf_properties_cache[name] = result
        return result

    def _tf_switch(self, **kwargs):
        """ Remove the mapping with the local folder and map/update it again
        in the new location.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_switch '
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        # Change the mapping:
        self._tf_workfold_unmap(**kwargs)
        return self._tf_checkout(**kwargs)

    def _tf_update(self, **kwargs):
        """ Retrieves a copy from the server.
        tf syntax:
        tf get [itemspec] [/version:versionspec] [/all] [/overwrite] [/force]
        [/preview] [/recursive] [/remap] [/noprompt] [/login:username,[password]]
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_update '
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        args = [TF, "get", "-recursive", path]
        self._tf_append_argument(args,['profile','login','version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("tf get of '%s' failed.\n%s" % (name, stderr))
        if kwargs.get('verbose', False):
            return stdout

    def tf_checkout(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' tf_checkout '
        name = self.source['name']
        path = self.source['path']
        if os.path.exists(path):
            self.output((logger.info, "Skipped checkout of existing package '%s'." % name))
            return
        self.output((logger.info, "Checked out '%s' with microsoft team foundation." % name))
        return self._tf_error_wrapper(self._tf_checkout, **kwargs)

    def tf_switch(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' tf_switch '
        name = self.source['name']
        self.output((logger.info, "Switched '%s' with microsoft team foundation." % name))
        return self._tf_error_wrapper(self._tf_switch, **kwargs)

    def tf_update(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' tf_update '
        name = self.source['name']
        self.output((logger.info, "Updated '%s' with microsoft team foundation." % name))
        return self._tf_error_wrapper(self._tf_update, **kwargs)

    def checkout(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)#", ' checkout '
        name = self.source['name']
        path = self.source['path']
        update = self.should_update(**kwargs)
        if os.path.exists(path):
            matches = self.matches()
            if matches:
                if update:
                    self.update(**kwargs)
                else:
                    self.output((logger.info, "Skipped checkout of existing package '%s'." % name))
            else:
                if self.status() == 'clean':
                    return self.tf_switch(**kwargs)
                else:
                    raise TFError("Can't switch package '%s' to '%s' because it's dirty." % (name, self.source['url']))
        else:
            return self._tf_error_wrapper(self.tf_checkout, **kwargs)

    def _tf_preview_clean(self, **kwargs):
        """
        Check/preview changes from local folder.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_preview_clean '
        name = self.source['name']
        path = self.source['path']
        url = self.source['url']

        # get from server
        args = [TF, "get", "-preview", "-recursive", path]
        self._tf_append_argument(args,['profile','login','version'])
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)
        if returncode != 0:
            raise TFError("'tf get -preview' for '%s' failed.\n%s" % (name, stderr))
        return STDOUT_EXP_GET_PREVIEW_OK in stdout

    def matches(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)#", ' matches >'

        props = self._tf_error_wrapper(self._tf_properties, **kwargs)
        if props:
            preview_clean = self._tf_error_wrapper(self._tf_preview_clean, **kwargs)
            url = self.source['url']
            ret = info.get('url') == url and preview_clean
        else:
            # No properties (folder is not mapped)
            ret = False
        print "(DEBUG  TF)#", ' matches < return:',ret
        return ret

    def _tf_status_clean(self, **kwargs):
        """
        Check/preview changes from local folder.
        """
        #TODO: Remove this
        print "(DEBUG  TF)  ", ' _tf_status_clean '
        name = self.source['name']
        path = self.source['path']

        # get from server
        args = [TF, "status", "-recursive", path]
        self._tf_append_argument(args,['workspace','profile','login'])        
        stdout, stderr, returncode = self._tf_communicate(args, **kwargs)

        if returncode != 0:
            raise TFError("'tf status' for '%s' failed.\n%s" % (name, stderr))
        return STDOUT_EXP_STATUS_OK in stdout, stdout

    def deactivate(self, **kwargs):
        print "OK"
        import pdb; pdb.set-trace()

    def status(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)#", ' status >'
        clean, stdout = self._tf_error_wrapper(self._tf_status_clean, **kwargs)

        if clean:
            status = 'clean'
        else:
            status = 'dirty'

	print "(DEBUG  TF)#", ' status < return:',status
        if kwargs.get('verbose', False):
            return status, stdout
        else:
            return status

    def update(self, **kwargs):
        #TODO: Remove this
        print "(DEBUG  TF)#", ' update '
        name = self.source['name']
        force = kwargs.get('force', False)
        status = self.status()
        #Switch
        if not self.matches():
            if force or status == 'clean':
                return self._tf_error_wrapper(self.tf_switch, **kwargs)
            else:
                raise TFError("It was not possibel to switch '%s' to the new location."
                              "There are uncommited changes") 
#        always update an maintain local changes
#        if status != 'clean' and not force:
#            raise TFError("Update aborted!  upCan't update package '%s' because it has local changes ()." % name)
        #Update
        return self.tf_update(**kwargs)

common.workingcopytypes['tf'] = TFWorkingCopy
