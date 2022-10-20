"""
Extremely simple example of NoKnow ZK Proof implementation
"""
from getpass import getpass
from noknow.core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from queue import Queue
from threading import Thread


def client (iq: Queue, oq: Queue):
  client_zk = ZK.new (curve_name="secp256k1", hash_alg="sha3_256")

  # Create signature and send to server
  signature = client_zk.create_signature (getpass ("Enter Password: "))
  oq.put (signature.dump ())

  # Receive the token from the server
  token = iq.get ()

  # Create a proof that signs the provided token and sends to server
  proof = client_zk.sign (getpass ("Enter Password Again: "), token).dump ()

  # Send the token and proof to the server
  oq.put (proof)

  # Wait for server response!
  print ("Success!" if iq.get () else "Failure!")


def server (iq: Queue, oq: Queue):
  # Set up server component
  server_password = "SecretServerPassword"
  server_zk = ZK.new (curve_name="secp384r1", hash_alg="sha3_512")
  server_signature: ZKSignature = server_zk.create_signature ("SecureServerPassword")

  # Load the received signature from the Client
  sig = iq.get ()
  client_signature = ZKSignature.load (sig)
  client_zk = ZK (client_signature.params)

  # Create a signed token and send to the client
  token = server_zk.sign ("SecureServerPassword", client_zk.token ())
  oq.put (token.dump (separator=":"))

  # Get the token from the client
  proof = ZKData.load (iq.get ())
  token = ZKData.load (proof.data, ":")

  # In this example, the server signs the token so it can be sure it has not been modified
  if not server_zk.verify (token, server_signature):
    oq.put (False)
  else:
    oq.put (client_zk.verify (proof, client_signature, data=token))


def main ():
  print (f'Hello World')

  # Create signature and send to server
  client___password = "someclientpassword"
  client__zk = ZK.new (curve_name="secp256k1", hash_alg="sha3_256")
  client__signature = client__zk.create_signature (client___password)
  comms1 = client__signature.dump ()
  print ("From client to server: " + comms1)  # sending


  # Set up server component
  server__password = "SecretServerPassword"
  server__zk = ZK.new (curve_name="secp384r1", hash_alg="sha3_512")
  server__signature: ZKSignature = server__zk.create_signature (server__password)
  # Load the received signature from the Client
  server__client_signature = ZKSignature.load (comms1)  # receiving
  server__client_zk = ZK (server__client_signature.params)
  # Create a signed token and send to the client
  server__token = server__zk.sign (server__password, server__client_zk.token ())
  comms2 = server__token.dump (separator=":")
  print ("From server to client: " + comms2)  # sending


  # Receive the token from the server &  Create a proof that signs the provided token and sends to server
  comms3 = client__zk.sign (client___password, comms2).dump ()  # receiving
  print ("From client to server: " + comms3)  # sending


  # Get the token from the client
  proof = ZKData.load (comms3)  # receiving
  server__token = ZKData.load (proof.data, ":")
  # In this example, the server signs the token so it can be sure it has not been modified
  if not server__zk.verify (server__token, server__signature):
    print ("Failure!")
  else:
    print (server__client_zk.verify (proof, server__client_signature, data=server__token))


  # q1, q2 = Queue (), Queue ()
  # threads = [
  #   Thread (target=client, args=(q1, q2)),
  #   Thread (target=server, args=(q2, q1)),
  # ]
  # for func in [Thread.start, Thread.join]:
  #   for thread in threads:
  #     func (thread)

  print (f'Goodbye World')


if __name__ == "__main__":
  main ()
