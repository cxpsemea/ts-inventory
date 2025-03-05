import sys
from shared.package.common.cxconfig import CxConfigError
from shared.package.common.cxconfig import cxconfig
from shared.package.common.cxlogging import ERROR
from shared.package.common.cxlogging import cxlogger
from src.configuration import config_settings
from src.cxsastinventory import CxSastInventory
from src.cxscainventory import CxScaInventory


# from src.cxoneinventory import CxOneInventory


def execute() :
    errorcount: int = 0


    # Activate logging
    cxlogger.activate(jsonformat = False, rebase = True)

    # Display header info
    try :
        # Verbose the header
        cxlogger.verbose( '' )
        cxlogger.verbose( '=============================================================================' )
        cxlogger.verbose( 'Checkmarx Inventory Tool' )
        cxlogger.verbose( '© Checkmarx. All rights reserved.' )

        # Process config
        cxconfig.add_defs( config_settings )
        try :
            cxconfig.activate()

            # Selection according to target system
            if cxconfig.hascommand('sast') :

                runner: CxSastInventory = CxSastInventory()
                errorcount += runner.execute()

            # elif cxconfig.hascommand('cxone') :

            #     runner: CxOneInventory = CxOneInventory()
            #     errorcount += runner.execute()

            elif cxconfig.hascommand('sca') :

                runner: CxScaInventory = CxScaInventory()
                errorcount += runner.execute()

            else :
                if cxlogger.loglevel <= ERROR :
                    cxlogger.error( 'No valid command found for execution' )
                else :
                    cxlogger.verbose( 'No valid command found for execution' )
                errorcount += 1

        except CxConfigError as e :
            xmsg: str = str(e)
            if cxlogger.loglevel > ERROR :
                cxlogger.verbose( xmsg )
            errorcount += 1
        except Exception :
            pass

    finally :
        # Verbose the footer
        cxlogger.verbose( '' )

    # Give an exit code en errors
    if errorcount > 0 :
        sys.exit(1)


# Only run if this is the application main root
if __name__ == '__main__' :
    execute()
