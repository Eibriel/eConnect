from econnect import app

import os
import cf_deployment_tracker

# Emit Bluemix deployment event
cf_deployment_tracker.track()

port = int(os.getenv('PORT', 5000))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=port)
