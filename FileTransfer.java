import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * 
 * Mark Erickson
 * CS 380 P7
 *
 */

public class FileTransfer {

	private int seqNum;
	private Key aesKey;

	FileTransfer(){

		seqNum = 0;
	}

	public void setKey(Key key){
		aesKey = key;
	}

	public Key getKey(){
		return aesKey;
	}

	public void setSeqNum(int num){
		seqNum = num;
	}

	public int getSeqNum(){
		return seqNum;
	}


	public static void main(String[] args) {

		if (args.length < 1){
			System.out.println("This program needs at least one command line argument.");
			System.exit(0);
		}

		FileTransfer transfer = new FileTransfer();
		// Make Keys Argument
		if (args[0].equalsIgnoreCase("makekeys")){
			try {
				KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
				gen.initialize(4096); // you can use 2048 for faster key generation
				KeyPair keyPair = gen.genKeyPair();
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();
				try (ObjectOutputStream oos = new ObjectOutputStream(
						new FileOutputStream(new File("public.bin")))) {
					oos.writeObject(publicKey);
				}
				try (ObjectOutputStream oos = new ObjectOutputStream(
						new FileOutputStream(new File("private.bin")))) {
					oos.writeObject(privateKey);
				}
			} catch (NoSuchAlgorithmException | IOException e) {
				e.printStackTrace(System.err);
			}
		}
		// Server mode
		else if (args[0].equalsIgnoreCase("server")){
			if (args.length != 3){
				System.out.println("Server mode needs 3 command line arguments to run.");
				System.exit(0);
			}
			byte[] fileData = null;
			int chunkSize = 0;
			long fileSize = 0;
			int numOfChunks = 0;
			String privateKeyFile = args[1];
			int portNumber = Integer.parseInt(args[2]);
			try{
				ServerSocket server = new ServerSocket(portNumber,0,InetAddress.getByName(null));

				Socket socket = server.accept();
				OutputStream os = socket.getOutputStream();
				InputStream is = socket.getInputStream();
				ObjectOutputStream objectOut = new ObjectOutputStream(os);
				ObjectInputStream objectIn = new ObjectInputStream(is);
				Message readMessage;

				while (true){
					readMessage = (Message) objectIn.readObject();
					if (readMessage.getType() == MessageType.START){
						AckMessage initAck = new AckMessage(0); //0 to start connection -1 if connection refused. change later
						objectOut.writeObject(initAck);
						objectOut.flush();
						StartMessage clientStart = (StartMessage) readMessage;
						fileSize = clientStart.getSize();
						chunkSize = clientStart.getChunkSize();
						transfer.setSeqNum(0);
						numOfChunks = (int) (fileSize / chunkSize);
						fileData = new byte[(int) clientStart.getSize()];
						byte[] encryptedAESKey = clientStart.getEncryptedKey();

						Cipher rsa = Cipher.getInstance("RSA");
						ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(privateKeyFile)); //Getting the receiver's private key from the file.
						PrivateKey privateKey = (PrivateKey) privateKeyIS.readObject(); // Private Key object
						privateKeyIS.close();
						rsa.init(Cipher.UNWRAP_MODE, privateKey); // Initialize the cipher in unwrap mode.
						Key key = (Key) rsa.unwrap(encryptedAESKey, "AES", Cipher.SECRET_KEY);
						transfer.setKey(key);
					}
					else if (readMessage.getType() == MessageType.STOP){
						//Throw away file transfer
						fileData = null;
						transfer.setSeqNum(0);
						AckMessage terminateConnection = new AckMessage(-1);
						objectOut.writeObject(terminateConnection);

					}

					else if (readMessage.getType() == MessageType.CHUNK){
						Cipher aes = Cipher.getInstance("AES");
						Key key = transfer.getKey();
						aes.init(Cipher.DECRYPT_MODE, key); //Initialize object to decrypt the message using the AES key.
						Chunk chunk = (Chunk) readMessage;
						int nextSequenceNum = transfer.getSeqNum();
						if (chunk.getSeq() == nextSequenceNum){
							byte[] plainText = aes.doFinal(chunk.getData());
							int crcFromChunk = chunk.getCrc();
							CRC32 crc = new CRC32();
							crc.update(plainText);
							int decryptedCrc = (int) crc.getValue();
							if (crcFromChunk == decryptedCrc){
								byte[] readData = plainText;
								int offset = nextSequenceNum * chunkSize;
								for (int i=0;i<readData.length;i++){
									if (offset >= fileSize){
										break;
									}
									fileData[offset] = readData[i];
									offset++;
								}
								System.out.println("Chunk Received [" + nextSequenceNum + "/" + numOfChunks + "]");
								nextSequenceNum += 1;
								transfer.setSeqNum(nextSequenceNum);
								AckMessage acknowledment = new AckMessage(nextSequenceNum);
								objectOut.writeObject(acknowledment);
							}
							else{
								System.out.println("The CRC did not match.");
								break;
							}
						}
						if (numOfChunks == chunk.getSeq()){
							Scanner keyboard = new Scanner(System.in);
							String fileName = "";
							System.out.print("Enter the name of the file you want to create: ");
							fileName = keyboard.nextLine();
							File newFile = new File(fileName);
							FileOutputStream fos = new FileOutputStream(newFile);
							fos.write(fileData);
							fos.close();
							transfer.setSeqNum(0);
						}

					}
				}
				System.out.println("Server closed.");
				server.close();

			} catch(Exception e){
				System.out.println("Connection terminated.");
			}
		}
		// Client mode
		else if (args[0].equalsIgnoreCase("client")){
			try{
				Cipher AesCipher = Cipher.getInstance("AES");
				String publicKeyFile = args[1];
				String hostName = args[2];
				int portNumber = Integer.parseInt(args[3]);
				KeyGenerator keyGen = null;

				Socket socket = new Socket(InetAddress.getByName(hostName),portNumber);
				OutputStream os = socket.getOutputStream();
				InputStream is = socket.getInputStream();
				ObjectOutputStream objectOut = new ObjectOutputStream(os);
				ObjectInputStream objectIn = new ObjectInputStream(is);
				try {
					boolean flag = true;
					while(flag){
						keyGen = KeyGenerator.getInstance("AES");

						// Uses the KeyGenerator class's getInstance method to get a random symmetric key for AES.
						keyGen.init(256); // This initializes the KeyGenerator object to use a 256 bit AES key.
						SecretKey key = keyGen.generateKey();
						byte[] cipherTextAESKey = null;
						Cipher RSACipher = Cipher.getInstance("RSA"); // The type of RSA to be used.
						ObjectInputStream pubKeyIS = new ObjectInputStream(new FileInputStream(publicKeyFile)); //Getting the receiver's public key from the file.
						PublicKey publicKey = (PublicKey) pubKeyIS.readObject(); //Getting public key from file.
						RSACipher.init(Cipher.WRAP_MODE, publicKey); // Initialize the cipher in wrap mode.
						cipherTextAESKey = RSACipher.wrap(key); //Wrapping the AES key with the receiver's RSA public key.
						pubKeyIS.close();
						Scanner keyboard = new Scanner(System.in);
						String filePath = "";
						System.out.print("Enter path: ");
						filePath = keyboard.nextLine();
						File checkingPath = new File(filePath);
						if (!checkingPath.exists()){
							System.out.println("The file does not exist.");
							System.exit(0);
						}
						long fileSize = checkingPath.length();
						RandomAccessFile file = new RandomAccessFile(checkingPath,"r");
						int chunkSize = 1024; //Default 
						System.out.print("Enter the chunk size [1024]:");
						chunkSize = keyboard.nextInt();
						System.out.println("Sending: " + checkingPath);
						System.out.println("File size: " + fileSize);
						int totalChunks = (int) (fileSize / chunkSize);

						StartMessage start = new StartMessage(filePath,cipherTextAESKey,chunkSize);
						objectOut.writeObject(start);

						AckMessage ack = (AckMessage) objectIn.readObject(); //Get first ack
						int totalDataSent = 0;
						int localSeqNum = 0;
						byte[] chunkedData = new byte[chunkSize];
						if (ack.getSeq() == 0){
							while (totalDataSent < fileSize){
								file.read(chunkedData, 0, chunkSize);
								//file.skipBytes(chunkSize);
								System.out.println("Chunks completed: [" + localSeqNum + "/" + totalChunks + "]");
								CRC32 crc = new CRC32();
								crc.update(chunkedData);
								int plainTextCrc = (int) crc.getValue();

								//Encrypting data
								AesCipher.init(Cipher.ENCRYPT_MODE, key);
								byte[] encVal = AesCipher.doFinal(chunkedData);

								Chunk nextChunk = new Chunk(localSeqNum,encVal,plainTextCrc);
								objectOut.writeObject(nextChunk);
								totalDataSent += chunkSize;
								localSeqNum++;
								transfer.setSeqNum(localSeqNum);
								ack = (AckMessage) objectIn.readObject();
								if (ack.getSeq() != localSeqNum){
									System.out.println("The acknowledgment received was incorrect.");
								}
							}
						}
						else if (ack.getSeq() == -1){
							System.out.println("An error occured.");
						}

						file.close();
						System.out.print("Do you want to do another transfer (y/n):");
						keyboard.nextLine();
						String input = keyboard.nextLine();
						if (! input.equalsIgnoreCase("y")){
							flag = false;
							keyboard.close();
						}
					}
				}catch(Exception e){
					e.printStackTrace();
				}

			} catch(Exception e){
				e.printStackTrace();
			}

		}
	}
}
