package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

public class SimpleDNS
{
	private static String serverName;
	private static Map<String, String> ec2Table;
	private static DatagramSocket serverSocket;
	private final static int CLIENT_DNS_PORT = 8053;
	private final static int QUERY_DNS_PORT = 53;
	private final static int MAX_PACKET_SIZE = 1024;

	public static void main(String[] args) {
		System.out.println("Hello, DNS!");


		if (args.length != 4) {
			System.out.println("Invalid Arguments!");
			return;
		}
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-r")) {
				serverName = args[++i];
			} else if (args[i].equals("-e")) {
				ec2Table = loadEC2Table(args[++i]);
			} else {
				System.out.println("Invalid Arguments!");
				return;
			}
		}
		// open a socket
		startDnsServer();
	}

	private static void startDnsServer(){

		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DNS dnsPacket;
		DNSQuestion question;

		try {
			serverSocket = new DatagramSocket(CLIENT_DNS_PORT);
			System.out.println("Socket initialization succeeded, listening...(root server is " + serverName + ")");
			while(true){
				DatagramPacket dnsReceived = new DatagramPacket(buffer, buffer.length);
				serverSocket.receive(dnsReceived);
				System.out.println("Received client DNS query");
				dnsPacket = DNS.deserialize(buffer, buffer.length);
				if (dnsPacket.getOpcode() != DNS.OPCODE_STANDARD_QUERY){
					// Only listening to standard queries
					continue;
				}
				question = dnsPacket.getQuestions().get(0);
				Short[] validTypes = {DNS.TYPE_A, DNS.TYPE_AAAA, DNS.TYPE_CNAME, DNS.TYPE_NS};
				Set<Short> validDnsTypes = new HashSet<Short>(Arrays.asList(validTypes));
				if (!validDnsTypes.contains(question.getType())){
					continue;
				}
				System.out.println("--------------Handling DNS query-----------------");
				handleDnsQuery(dnsPacket, dnsReceived);
			}
		} catch (SocketException e) {
			System.out.println("Server socket initialization failed!");
			e.printStackTrace();
			serverSocket.close();
			System.exit(1);
		} catch (IOException i) {
			i.printStackTrace();
			serverSocket.close();
			System.exit(1);
		}
		serverSocket.close();
	}

	private static void handleDnsQuery(DNS dnsPacket, DatagramPacket dnsReceived) throws IOException {

		// Check NS then reply to client, if in EC2, add a TXT record to reply
		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DatagramPacket query;
		DNSQuestion question = dnsPacket.getQuestions().get(0);
		InetAddress serverAddress = InetAddress.getByName(serverName);
		DatagramSocket socket = new DatagramSocket(QUERY_DNS_PORT);
		DNS toSendToClient = dnsPacket;
		boolean done = false;

		while(!done) {
			query = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), serverAddress, QUERY_DNS_PORT);
			// This socket is used to send query to server
			socket.send(query);
			System.out.println("Sent query to server " + serverAddress.toString());
			socket.setSoTimeout(1000);
			try {
				socket.receive(new DatagramPacket(buffer, buffer.length));
			} catch (SocketTimeoutException s) {
				System.out.println("Didn't receive answer from server " + serverAddress.toString());
				done = true;
			}
			System.out.println("Received answer from server " + serverAddress.toString());
			dnsPacket = DNS.deserialize(buffer, buffer.length);
			List<DNSResourceRecord> rootAnswers = dnsPacket.getAnswers();
			List<DNSResourceRecord> rootAuthorities = dnsPacket.getAuthorities();
			List<DNSResourceRecord> rootAdditional = dnsPacket.getAdditional();
			if(!dnsPacket.isRecursionDesired()){
				// Send back to client
				sendDNSReply(dnsPacket, dnsReceived);
				done = true;
			} else {
				//TODO: This part has problem, when NS replies an SOA, serverAddress doesnot update, thus goes to infinite looping
				if (rootAnswers.isEmpty()) {
					// if original query was NS, then done.
					if (question.getType() == DNS.TYPE_NS) {
						toSendToClient.setQuestions(dnsPacket.getQuestions());
						toSendToClient.setAnswers(dnsPacket.getAdditional());
						sendDNSReply(dnsPacket, dnsReceived);
					}
					for (DNSResourceRecord auth : rootAuthorities) {
						boolean found = false;
						if (auth.getType() != DNS.TYPE_NS) {
							continue;
						}
						DNSRdataName nsName = (DNSRdataName) auth.getData();
						for (DNSResourceRecord additional : rootAdditional) {
							if (additional.getType() == DNS.TYPE_A && nsName.getName().equals(additional.getName())) {
								DNSRdataAddress addressData = (DNSRdataAddress) additional.getData();
								String addressName = addressData.toString();
								serverAddress = InetAddress.getByName(addressName);
								System.out.println("Query to another NS " + serverAddress.toString());
								found = true;
							}
						}
						if (found) break;
					}
					// Add additionals, authorities to reply
					toSendToClient.setAdditional(rootAdditional);
					toSendToClient.setAuthorities(rootAuthorities);

				} else { // Hold toSendToClient until get answers
					DNSResourceRecord rootAns = rootAnswers.get(0);
					if (rootAns.getType() == DNS.TYPE_CNAME){
						DNSQuestion nextQuestion = new DNSQuestion();
						DNSRdataName dnsRdataname = (DNSRdataName) rootAns.getData();
						nextQuestion.setName(dnsRdataname.getName());
						nextQuestion.setType(question.getType());
						dnsPacket.setQuestions(Collections.singletonList(nextQuestion));
					} else {
						toSendToClient.setAnswers(rootAnswers);
						sendDNSReply(toSendToClient, dnsReceived);
						done = true;
					}
				}
			}
			prepareNewQuery(dnsPacket);
		}
		socket.close();
	}

	private static void prepareNewQuery(DNS dnsPacket){
		dnsPacket.setQuery(true);
		dnsPacket.setRecursionAvailable(true);
		dnsPacket.setRecursionDesired(true);
		// remove already sent additionals and authorities
		for (int i = 0; i < dnsPacket.getAdditional().size(); i++){
			dnsPacket.removeAdditional(dnsPacket.getAdditional().get(i));
		}
		for (int i = 0; i < dnsPacket.getAuthorities().size(); i++){
			dnsPacket.removeAuthority(dnsPacket.getAuthorities().get(i));
		}
	}

	private static void sendDNSReply(DNS dnsPacket, DatagramPacket dnsReceived) throws IOException{
		if(dnsPacket.getQuestions().get(0).getType() == DNS.TYPE_A){
			System.out.println("********** Checking if in EC2 regions ************");
			checkIfInEC2(dnsPacket);
			System.out.println("************** Checking done *********************");
		}
		DatagramPacket ans = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), dnsReceived.getSocketAddress());
		serverSocket.send(ans);
		System.out.println("Sent answer to client");
	}

	/** Map(ip/subnetLength -> geoLocation) */
	private static Map<String, String> loadEC2Table(String file) {
		System.out.println("Loading static EC2 table from " + file);
		Map<String, String> ec2Map = new HashMap<String, String>();
		BufferedReader br = null;
		String line;
		String cvsDelimiter = ",";
		try {
			br = new BufferedReader(new FileReader(file));
			while ((line = br.readLine()) != null) {
				String[] entry = line.split(cvsDelimiter);
				String ip = entry[0];
				String location = entry[1];
				ec2Map.put(ip, location);
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		System.out.println("Loaded static EC2 table from " + file);
		return ec2Map;
	}

	private static void checkIfInEC2(DNS dnsPacket){
		if(dnsPacket.getAdditional().size() > 0){
			for (int i = 0; i < dnsPacket.getAnswers().size(); i++) {
				if (dnsPacket.getAnswers().get(i).getType() != DNS.TYPE_A){
					System.out.println("Not an IPv4 address");
					continue;
				}
				DNSRdataAddress addressData = (DNSRdataAddress) dnsPacket.getAnswers().get(i).getData();
				String addressString = addressData.getAddress().toString();
				String ipStr = addressString.substring(addressString.indexOf("/") + 1); // e.g. 73.252.22.1
				for (String entry : ec2Table.keySet()) {
					long ip = parseIp(ipStr);
					long subnet = parseIp(entry.substring(0, entry.indexOf("/")));
					int subnetLength = Integer.parseInt(entry.substring(entry.indexOf("/") + 1));
					long subnetBits = 0xffffffff - ((1 << (32 - subnetLength)) - 1);
					if ((subnetBits & ip) == (subnetBits & subnet)) {
						System.out.println("This IP is in EC2!");
						// Found in EC2, add to records
						String location = ec2Table.get(entry);
						DNSRdataString txt = new DNSRdataString(location + "-" + ip);
						DNSResourceRecord record = new DNSResourceRecord();
						record.setType(DNS.TYPE_TXT);
						record.setName(addressData.toString());
						record.setData(txt);
						dnsPacket.addAnswer(record);
					} else {
						System.out.println("This IP is NOT in EC2!");
					}
				}
			}
		}
	}

	private static long parseIp(String address) {
		long result = 0;

		// iterate over each octet
		for(String part : address.split(Pattern.quote("."))) {
			// shift the previously parsed bits over by 1 byte
			result = result << 8;
			// set the low order bits to the current octet
			result |= Integer.parseInt(part);
		}
		return result;
	}
}
