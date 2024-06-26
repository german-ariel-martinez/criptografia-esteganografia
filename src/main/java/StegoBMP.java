import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class StegoBMP {

    // Variables globales
    private static final int DATA_SIZE_BYTES = 4;


    public static void embed(File fileToHide, File bmp, String nout, String steg, String pass, String a, String m) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Nos fijamos que metodo de esteganografiado estamos utilizando
        // En base a esto vamos cuantos bits por byte contienen el archivo
        // que esta oculto: LSB1 -> 1bit / LSB4 -> 4 / LSBI -> 1
        int payloadBits = 1;
        boolean improved = false;
        if(steg.toLowerCase().equals("lsb4")) { payloadBits = 4; }
        else if (steg.toLowerCase().equals("lsbi")) { improved = true; }

        // Accedemos a los bytes del archivo BMP y los guardamos
        // en la variable bmpBytes
        FileInputStream bmpStream = new FileInputStream(bmp);
        byte[] bmpBytes = new byte[(int) bmp.length()];
        bmpStream.read(bmpBytes);

        int bmpHeader = ByteBuffer.wrap(bmpBytes, 10, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();

        FileInputStream fileToHideStream = new FileInputStream(fileToHide);
        byte[] fileHideBytes = new byte[(int) fileToHide.length()];
        fileToHideStream.read(fileHideBytes);

        int extensionStart = fileToHide.getName().lastIndexOf('.');
        String extension = fileToHide.getName().substring(extensionStart).concat("\0");

        // Tamanio minimo requerido
        int reqSize = 4 + fileHideBytes.length + extension.length();
        reqSize *= (8 / payloadBits); // Depende si tendre que poner 1bit por byte o 4
        reqSize += bmpHeader;

        if(bmp.length() <  reqSize)
            throw new RuntimeException(String.format("El archivo portador debe tener como minimo %d bytes\nPero tiene: %d", reqSize, bmp.length()));

        // Hay que saltear el header del archivo BMP y
        // En el caso de que sea LSBI los primeros 4 bytes
        // representan con un 1 o un cero que bits se invirtieron
        // segun el 2do y 3er bit menos significativo de cada byte.
        int from = bmpHeader + (improved ? 4 : 0);

        // Para encriptar necesitaremos el payload completo.
        // Ya que hacerlo por separado seria un error
        int sizeToHide = fileHideBytes.length;
        byte[] sizeToHideBytes = ByteBuffer.allocate(4).putInt(sizeToHide).array();

        byte[] entirePayload = ArrayUtils.addAll(sizeToHideBytes, fileHideBytes);
        entirePayload = ArrayUtils.addAll(entirePayload, extension.getBytes());

        if (pass != null){
            entirePayload = encrypt(entirePayload, pass, a, m);
        }

        // En caso de que sea LSBI debemos tener una copia para poder comparar los bytes que cambian
        byte[] originalBmp = bmpBytes.clone();

        encodeLSB(entirePayload, bmpBytes, from, payloadBits, improved);

        if(improved) {
            applyLSBI(bmpBytes, originalBmp, from);
        }

        // Guardar la imagen BMP modificada
        String filename = nout.concat(".bmp");
        File outputFile = new File(filename);
        FileOutputStream os = new FileOutputStream(outputFile);
        os.write(bmpBytes);
        os.close();

        System.out.println("(5) -- Finalizado");
    }

    public static void extract(File bmp, String nout, String steg, String pass, String a, String m) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        int payloadBits = 1;
        boolean improved = false;
        if(steg.toLowerCase().equals("lsb4")) { payloadBits = 4; }
        else if (steg.toLowerCase().equals("lsbi")) { improved = true; }

        FileInputStream bmpStream = new FileInputStream(bmp);
        byte[] bmpBytes = new byte[(int) bmp.length()];
        bmpStream.read(bmpBytes);

        int bmpHeader = ByteBuffer.wrap(bmpBytes, 10, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int from = bmpHeader + (improved ? 4 : 0);

        // En el caso de que sea LSBI tenemos que desinvertir algunos bits
        if (improved) reverseLSBI(bmpBytes, from);

        byte[] secretBytes = decodeLSB(payloadBits, bmpBytes, from, improved); //incluye la extension y los 4 bytes que me dicen el tamanio del cifrado

        // Si tenemos una contraseña entonces esta encriptado
        if (pass != null) secretBytes = decrypt(secretBytes, pass, a, m);

        // Obtengo el size del archivo secreto (se encuentra en los primeros 4 bytes)
        int secretFileSize = ByteBuffer.wrap(secretBytes, 0, 4).getInt();

        System.out.println("(3) -- Extraccion finalizada");
        /*
         * Lo que se encripta es: tamanio archivo (4) || datos archivo || extension
         * Hasta ahora en secretBytes tenemos ese paquete entero.
         * en secretFileSize tenemos el tamanio archivo
         *
         * Es decir que si hago secretBytes[4 + secretFileSize] deberia caer justo donde arranca la extension.
         * */
        System.out.println("(4) -- Generando archivo de output");

        if(secretBytes[DATA_SIZE_BYTES + secretFileSize] != '.')
            throw new RuntimeException("Error en la decodificacion.");

        String extension = "";
        for(int i= DATA_SIZE_BYTES + secretFileSize; secretBytes[i] != 0; i++){
            extension = extension.concat(new String(new byte[] {secretBytes[i]}, StandardCharsets.UTF_8));
        }

        //Creamos el out
        String filename = String.format("%s%s", nout, extension);
        File outputFile = new File(filename);
        FileOutputStream os = new FileOutputStream(outputFile);

        os.write(secretBytes, DATA_SIZE_BYTES, secretFileSize);
        System.out.println("(5) -- Finalizado");
    }


    private static byte[] decodeLSB(int nBits, byte[] bmpBytes, int from, boolean isLsbi) {
        ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();

        // Creamos una mascara para quedarnos con los n-bits menos significativos
        // Como funciona:
        // - agarra el 1 binario y lo mueve nBits posiciones a la izquierda (dentro de un byte)
        //   si es 4 ==> 1 << nBits = 0b10000
        // - se resta 1 ==> se establecen todos los bits desde el bit n hasta el bit 0 en 1
        //   luego 0b10000 = 0b1111
        int mask = (1 << nBits) - 1;

        // Nos movemos por los bytes del BMP buscando los bits
        // menos significativos
        if(isLsbi){
            for(int i = from; i < bmpBytes.length; i++) {
                //i+1 porque como hay 4 bytes extra de offset, estariamos arrancando desde el byte Green.
                //El siguiente es Red, por lo que hay que saltearlo, y ya el Otro es Blue.
                if((i+1) %3 != 0) {
                    // Extraemos el bit menos significativo del byte actual
                    // haciendo un AND bit a bit con la mascara
                    byte bits = (byte) (bmpBytes[i] & mask);
                    payloadStream.write(bits);
                }
            }
        }else{
            for(int i = from; i < bmpBytes.length; i++) {
                byte bits = (byte) (bmpBytes[i] & mask);
                payloadStream.write(bits);
            }
        }

        // Creamos el lugar donde juntaremos todos los bits en bytes
        byte[] payloadBytes = new byte[(int) Math.ceil(payloadStream.size() / (8/nBits))];
        // Convertimos los bits del mensaje oculto a bytes
        byte[] payloadBits = payloadStream.toByteArray();

        for (int i = 0; i < payloadBytes.length; i++) {
            for (int j = 0; j < (int) Math.ceil((8/nBits)); j++) {
                payloadBytes[i] = (byte) (payloadBytes[i] << nBits | payloadBits[i * (int) Math.ceil((8/nBits)) + j]);
            }
        }

        //Ahora en secretBytes tengo los bytes que estaba ocultando en el bmp

        return payloadBytes;

    }

    private static void encodeLSB(byte[] bytesToHide, byte[] bmpBytes, int from, int nBits, boolean isLsbi) {
        if(!isLsbi) {
            for (byte currByte : bytesToHide) {
                for (int bitIndex = 0; bitIndex < 8; bitIndex += nBits) {
                    int bitValue = (currByte >> (8 - nBits - bitIndex)) & ((1 << nBits) - 1);
                    bmpBytes[from] = (byte) ((bmpBytes[from] & ~((1 << nBits) - 1)) | bitValue);
                    from++;
                }
            }
        } else {
            for (byte currByte : bytesToHide) {
                // Recordar que tenemos 4 bytes extra para el patron y por ende arrancamos de Green. (el from ya contempla el +4)
                for (int bitIndex = 0; bitIndex < 8; bitIndex += nBits) {
                    if ((from + 1) % 3 != 0) {
                        int bitValue = (currByte >> (8 - nBits - bitIndex)) & ((1 << nBits) - 1);
                        bmpBytes[from] = (byte) ((bmpBytes[from] & ~((1 << nBits) - 1)) | bitValue);
                    }else{
                        bitIndex -= nBits; //dejo el bitIndex donde esta.
                    }
                    from++;

                }
            }

        }
    }

    private static void applyLSBI(byte[] modifiedBmp, byte[] originalBmp, int from) {
        int[] patterns = new int[4]; // {00,01,10,11}
        int[] patternChangeCount = new int[4];


        for(int i = from; i < originalBmp.length; i++){
            if((i+1) % 3 != 0) {
                int pattern = (originalBmp[i] & 0b00000110) >> 1; // Obtengo los 2 bits y luego moviendo a la derecha me queda un valor entre 0-3
                patterns[pattern]++;
                if (modifiedBmp[i] != originalBmp[i]) {
                    patternChangeCount[pattern] += 1;
                }
            }
        }

        for(int i = 0; i < patterns.length; i++) {
            int changed = patternChangeCount[i];
            int total = patterns[i];
            int unchanged = total - changed;

            //  lsb1(patron) || LSBI(lsb1(tamanio) || lsb1(archivo) || lsb1(ext))

            if(changed > unchanged) {
                for (int j = from; j < modifiedBmp.length; j++) {
                    //Si no es rojo y si el byte pertenece al pattern actual, lo invertimos
                    if (((j+1) % 3 != 0) && ((modifiedBmp[j] & 0b00000110) >> 1) == i) {
                        modifiedBmp[j] ^= 1; // Invertimos el ultimo bit
                    }
                }
                // Agregamos aplicando LSB1 el bit que se relaciona con el pattern en los primeros 4 bytes
                // En este caso estariamos en (true), es decir, este patron flippeo
                modifiedBmp[from - 4 + i] |= 0b00000001;
            } else {
                // este patron no flipeo, (false)
                modifiedBmp[from - 4 + i] &= 0b11111110;
            }
        }
    }

    private static byte[] reverseLSBI(byte[] bmpBytes, int offset) {
        // Nos fijamos que bits se invirtieron
        // Seguimos el orden de patrones:
        //                            00      01     10     11
        boolean[] invertedPaterns = {false, false, false, false};

        // Nos fijamos en los primeros 4 bytes del BMP cuales patrones fueron invertidos
        for (int i = 0; i < 4; i++) {
            // Si el ultimo bit de cada byte esta en uno es que ese patron esta invertido
            if ((bmpBytes[offset - 4 + i] & 1) == 1) {
                invertedPaterns[i] = true;
            }
        }
        // Ahora tenemos que deshacer este cambio para seguir con la esteganografica normal
        // recordemos que el offset ya esta desplazado HEADERSIZE + 4 bytes de patterns
        for (int i = offset; i < bmpBytes.length; i++) {
            // Agarramos el byte, aplicamos una mascara para quedarnos con el
            // 2do y 3er bit solamente, despues movemos una posicion a la
            // derecha para que al castearlo como int nos matchee con el array de booleans
            int pattern = (bmpBytes[i] & 0b00000110) >> 1;
            // Este algoritmo no usa informacion en los bytes de color rojo, los usa
            // para generar ruido y aumentar la seguridad. Recordemos que para un pixel
            /// se usa RGB pero a nivel byte esta como BGR (un byte por color), luego
            // i+1 porque estamos un byte RGB desfasados debido a los 4 de patrones.
            // Salteamos los bytes rojos...
            if((i+1) % 3 != 0) {
                if (invertedPaterns[pattern]) {
                    if ((bmpBytes[i] & 1) == 1) {
                        // Si el ultimo es un uno lo invertimos con un &
                        bmpBytes[i] &= 0b11111110;
                    } else {
                        // Si el ultimo es un cero tenemos que invertirlo con un |
                        bmpBytes[i] |= 0b00000001;
                    }
                }
            }
        }
        return bmpBytes;
    }

    static byte[] generateKeyAndIv(String password, byte[] salt, int iterationCount, int keyLength, int ivLength) throws NoSuchAlgorithmException,  InvalidKeySpecException {
        // Creamos la especificacion de la clave
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength+ivLength);
        // Generamos una fabrica de claves para PBKDF2 con HMAC y SHA-256
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // Generamos la clave y el IV que van a aparecer concatenados (devolvemos un byte[])
        return factory.generateSecret(spec).getEncoded();
    }

    private static byte[] decrypt(byte[] secretBytes, String pass, String a, String m) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Nos fijamos el tamanio de lo que esta encriptado,
        // primeros 4 bytes
        int encSize = ByteBuffer.wrap(secretBytes, 0, 4).getInt();
        // Nos agarramos los bytes del archivo (encriptado todavia)
        secretBytes = Arrays.copyOfRange(secretBytes, 4, encSize + 4);
        // Nos fijamos que algoritmo de cifrado usamos
        int keyLength = 0, ivLength = 0;
        String cipherType = "AES";
        switch(a.toLowerCase()){
            case "aes128":
                keyLength = 128; ivLength = 128;
                break;
            case "aes192":
                keyLength = 192; ivLength = 128;
                break;
            case "aes256":
                keyLength = 256; ivLength = 128;
                break;
            case "des":
                keyLength = 192; ivLength = 64;
                cipherType = "DESede";
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + a);
        }
        // Revisamos el metodo de encadenamiento a utilizar
        String paddingType = null;
        switch(m.toLowerCase()){
            case "cbc", "ecb":
                paddingType = "PKCS5Padding";
                break;
            case "cfb":
                paddingType = "NOPADDING";
                m = "CFB8";
                break;
            case "ofb":
                paddingType = "NOPADDING";
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + m);
        }
        // Generamos la key y el IV
        byte[] salt = {0, 0, 0, 0, 0, 0, 0, 0};
        byte[] keyAndIv = generateKeyAndIv(pass, salt, 10000, keyLength, ivLength);
        byte[] key = Arrays.copyOfRange(keyAndIv, 0, keyLength/8);
        byte[] iv = Arrays.copyOfRange(keyAndIv, keyLength/8, keyAndIv.length);

        // Decodificar la clave y el IV
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, cipherType);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Crear y configurar el objeto Cipher para desencriptar
        Cipher cipher = Cipher.getInstance(cipherType+"/"+m.toUpperCase()+"/"+paddingType);
        if(m.equalsIgnoreCase("ecb"))
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        else
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Decodificamos
        secretBytes = cipher.doFinal(secretBytes);

        return secretBytes;
    }

    private static byte[] encrypt(byte[] fileBytes, String pass, String a, String m) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        int keyLength = 0, ivLength = 0;
        String cipherType = "AES";
        switch (a.toLowerCase()) {
            case "aes128":
                keyLength = 128; ivLength = 128;
                break;
            case "aes192":
                keyLength = 192; ivLength = 128;
                break;
            case "aes256":
                keyLength = 256; ivLength = 128;
                break;
            case "des":
                keyLength = 192; ivLength = 64;
                cipherType = "DESede";
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + a);
        }

        // Determinamos el tipo de padding según el modo de encadenamiento
        String paddingType = null;
        switch (m.toLowerCase()) {
            case "cbc", "ecb":
                paddingType = "PKCS5Padding";
                break;
            case "cfb":
                paddingType = "NOPADDING";
                m = "CFB8";
                break;
            case "ofb":
                paddingType = "NOPADDING";
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + m);
        }

        // Generamos la clave y el IV
        byte[] salt = {0, 0, 0, 0, 0, 0, 0, 0};
        byte[] keyAndIv = generateKeyAndIv(pass, salt, 10000, keyLength, ivLength);
        byte[] key = Arrays.copyOfRange(keyAndIv, 0, keyLength / 8);
        byte[] iv = Arrays.copyOfRange(keyAndIv, keyLength / 8, keyAndIv.length);

        // Crear y configurar el objeto Cipher para encriptar
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, cipherType);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(cipherType + "/" + m.toUpperCase() + "/" + paddingType);
        if(m.equalsIgnoreCase("ecb")){
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } else
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Cifrar los datos
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        int encSize = encryptedBytes.length;


        // Preparar el resultado con el tamaño al inicio
        ByteBuffer bb = ByteBuffer.allocate(4 + encSize);
        bb.putInt(encSize);
        bb.put(encryptedBytes);

        return bb.array();

    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String byteToBinaryString(byte b) {
        StringBuilder binaryString = new StringBuilder();
        for (int i = 7; i >= 0; i--) {
            int bit = (b >> i) & 1;
            binaryString.append(bit);
        }
        return binaryString.toString();
    }
}
