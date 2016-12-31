package pl.angry.bbb;

import java.util.Scanner;

/**
 * A simple client that issues a CCR (credit-control request)
 */

class Client {
    public static final void main(String args[]) throws Exception {
        if(args.length!=4) {
            System.out.println("Usage: <host-id> <realm> <peer> <peer-port>");
            return;
        }

        String host_id = args[0];
        String realm = args[1];
        String dest_host = args[2];
        int dest_port = Integer.parseInt(args[3]);
        Scanner sc = new Scanner(System.in);
        String password = sc.nextLine();

        DiameterClient client = new DiameterClient(host_id, realm, dest_host, dest_port);
        client.setPassword(password);
        client.setUsername("user");
        client.setSecret("assdasfffsaf");
        client.start();
        client.runAaProcess();
        client.stop();


    }
}