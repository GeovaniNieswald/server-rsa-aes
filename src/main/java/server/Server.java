package server;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    private ServerSocket serverSocket;

    private SecretKey chaveAES;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public static void main(String[] args) {
        try {
            Server server = new Server();
            server.criarServerSocket(5555);

            boolean chavesOK = server.verificarChaves();

            if (chavesOK) {
                while (true) {
                    Socket socket = server.esperarConexao();
                    server.tratarConexao(socket);
                    System.out.println("---------------------------------------------------------");
                }
            } else {
                System.out.println("\nNao foi possivel iniciar processo, RSA Keys sao necessarias");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] base64ToByteArray(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private SecretKey stringToSecretKey(String secretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    private boolean verificarChaves() throws IOException {
        InputStream inPrivateKey = this.getClass().getResourceAsStream("/private.key");
        InputStream inPublicKey = this.getClass().getResourceAsStream("/public.key");

        boolean ok = false;

        if (inPrivateKey != null && inPublicKey != null) {
            ObjectInputStream inputPrivateK = new ObjectInputStream(inPrivateKey);
            ObjectInputStream inputPublicK = new ObjectInputStream(inPublicKey);

            try {
                this.privateKey = (PrivateKey) inputPrivateK.readObject();
                this.publicKey = (PublicKey) inputPublicK.readObject();

                ok = true;
            } catch (ClassNotFoundException ex) {
                ex.printStackTrace();
            }
        }

        inPrivateKey.close();
        inPublicKey.close();

        return ok;
    }

    private void criarServerSocket(int porta) throws IOException {
        System.out.println("---------------------------------------------------------");
        System.out.println("Criando Servidor...");
        this.serverSocket = new ServerSocket(porta);
        System.out.println("Servidor Criado");
    }

    private Socket esperarConexao() throws IOException {
        System.out.println("Aguardando Conexao...");
        Socket socket = this.serverSocket.accept();
        System.out.println("---------------------------------------------------------");
        System.out.println("Cliente Conectado\n");

        return socket;
    }

    private void tratarConexao(Socket socket) throws IOException {
        String msg;

        try {
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

            // ----------------- RECEBE PEDIDO DE CHAVE PUBLICA ------
            msg = input.readUTF();

            System.out.println("Entrada: " + msg);
            System.out.println("");
            // -------------------------------------------------------

            // ----------------- ENVIA CHAVE PUBLICA -----------------
            String strPublicKey = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
            output.writeObject(this.publicKey);
            output.flush();

            System.out.println("Saida: Chave Publica enviada");
            System.out.println("Chave Publica Crua: " + strPublicKey);
            System.out.println("");
            // -------------------------------------------------------

            // ----------------- RECEBE CHAVE AES CRIPTOGRAFADA ------
            String strChaveAEScripRSA = input.readUTF();
            byte[] chaveAEScripRSA = this.base64ToByteArray(strChaveAEScripRSA);
            String strChaveAES = CriptografiaRSA.descriptografar(chaveAEScripRSA, this.privateKey);

            System.out.println("Entrada: Chave AES Criptografada Recebida");
            System.out.println("Chave AES Criptografada com RSA: " + strChaveAEScripRSA);
            System.out.println("Chave AES Crua: " + strChaveAES);
            System.out.println("");

            this.chaveAES = this.stringToSecretKey(strChaveAES);
            // -------------------------------------------------------

            // ----------------- RECEBE LOGIN E SENHA ----------------
            String strLoginCripAES = input.readUTF();
            byte[] loginCriptografado = this.base64ToByteArray(strLoginCripAES);
            String login = CriptografiaAES.descriptografar(loginCriptografado, this.chaveAES);

            String strSenhaCripAES = input.readUTF();
            byte[] senhaCriptografada = this.base64ToByteArray(strSenhaCripAES);
            String senha = CriptografiaAES.descriptografar(senhaCriptografada, this.chaveAES);

            System.out.println("Entrada: Login e Senha Recebidos");
            System.out.println("Login Criptografado com AES: " + strLoginCripAES);
            System.out.println("Login Cru: " + login);
            System.out.println("Senha Criptografada com AES: " + strSenhaCripAES);
            System.out.println("Senha Crua: " + senha);
            // -------------------------------------------------------

            output.close();
            input.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            this.fecharSocket(socket);
        }
    }

    private void fecharSocket(Socket socket) throws IOException {
        socket.close();
        System.out.println("\nCliente Finalizado");
    }

}
