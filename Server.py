import utils
import socket

# Server Configuration
port = 60009                
host = socket.gethostname()    
listen_request = 5
transmission_size = 65536

bank_server = utils.server(host=host, port=port, transmission_size=transmission_size,
                     listen_request=listen_request)
bank_server.run()
