
# When transforming an exclusion to a glob, the exclusion is really a negation.
# That means that file exclusions like:
# - *.tmp  should be prefixed with !, resulting in !*.tmp
# To achieve that, set the param invertnegate to True
# Otherwise, set the param invertnegate to False


class globfilters(object) :


    # class methods returning arrays (or None)

    @classmethod
    def filefilter( self, filter: str = None, invertnegate: bool = True ) :
        globfilter = []
        # Returs an array
        if filter :
            for item in filter.split(',') :
                if item.strip() :
                    item = item.replace('\\','/').strip()
                    if not (item.startswith('!/') or item.startswith('/')) :
                        if item.startswith('!') :
                            item = '!**/' + item[1:0]
                        else :
                            item = '**/' + item
                    if invertnegate :
                        if item.startswith('!') :
                            globfilter.append( item[1:0] )  
                        else :
                            globfilter.append( '!' + item )  
                    else :
                        if item.startswith('!') :
                            globfilter.append( '!' + item[1:0] )  
                        else :
                            globfilter.append( item )  
        if len(globfilter) == 0 :
            return None
        return globfilter
    
    @classmethod
    def folderfilter( self, filter: str = None, invertnegate: bool = True ) :
        globfilter = []
        # Returs an array
        if filter :
            for item in filter.split(',') :
                if item.strip() :
                    if invertnegate :
                        if item.startswith('!') :
                            globfilter.append( '**/' + item.replace('\\','/')[1:0].strip() + '/**' )  
                        else :
                            globfilter.append( '!**/' + item.replace('\\','/').strip() + '/**' )  
                    else :
                        if item.startswith('!') :
                            globfilter.append( '!**/' + item.replace('\\','/')[1:0].strip() + '/**' )  
                        else :
                            globfilter.append( '**/' + item.replace('\\','/').strip() + '/**' )  
        if len(globfilter) == 0 :
            return None
        return globfilter 
    
    @classmethod
    def filters( self, filefilter: str = None, folderfilter: str = None, invertnegate: bool = True ) :
        globfilter = []
        xfilter = globfilters.filefilter( filefilter, invertnegate )
        if xfilter :
            globfilter.extend( xfilter )
        xfilter = globfilters.folderfilter( folderfilter, invertnegate )
        if xfilter :
            globfilter.extend( xfilter )
        if len(globfilter) == 0 :
            return None
        return globfilter

    # Class methods returning strings (or None)

    @classmethod
    def getfilefilter( self, filter: str = None, invertnegate: bool = True ) :
        globfilter = globfilters.filefilter( filter, invertnegate )
        if globfilter :
            return ','.join(globfilter)
        else :
            return None

    @classmethod
    def getfolderfilter( self, filter: str = None, invertnegate: bool = True ) :
        globfilter = globfilters.folderfilter( filter, invertnegate )
        if globfilter :
            return ','.join(globfilter)
        else :
            return None
        
    @classmethod                        
    def getfilters( self, filefilter: str = None, folderfilter: str = None, invertnegate: bool = True ) :
        globfilter = globfilters.filters( filefilter, folderfilter, invertnegate )
        if globfilter :
            return ','.join(globfilter)
        else :
            return None
