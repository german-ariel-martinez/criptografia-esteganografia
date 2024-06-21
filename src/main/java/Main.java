import org.apache.commons.cli.*;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    // Variables globales
    static final int BMP_HEADER_SIZE = 54;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Definimos los parametros que acepta por linea de comandos la aplicacion
        // Para esto usamos el objeto Options de la libreria de commons-cli
        Options op = new Options();

        // Sintaxis: Option(comando corto, comando largo, si recibe un parametro, descripcion)
        op.addOption("em", "embed", false, "Indica que se va a ocultar informacion en un archivo BMP.");
        op.addOption("in", true, "Archivo que se va a ocultar.");
        op.addOption("ex", "extract", false, "Indica que se va a extraer informacion de un archivo BMP.");
        op.addOption("p", true, "Archivo BMP del cual extraemos/metemos informacion.");
        op.addOption("out", true, "Nombre del archivo de salida a obtener.");
        op.addOption("steg", true, "Algoritmo de esteganografiado: <LSB1 | LSB4 | LSBI>");
        op.addOption("a", true, "Cifrado: <aes128 | aes192 | aes256 | des>");
        op.addOption("m", true, "Modo de encadenamiento a utilizar: <ecb | cfb | ofb | cbc>");
        op.addOption("pass", true, "Contraseña de encripcion");

        // Creamos un parser para las opciones
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        // Intentamos interpretar lo que ingreso el usuario
        try {
            cmd = parser.parse(op, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("Como usar el programa de estaganografiado...", op);
            System.exit(1);
        }

        // Si llegamos aca ingresamos bien las cosas, luego podemos:
        // - usar la opcion de extraer (-extract)
        // - usar la opcion de ocultar (-embed)

        // Donde guardamos el archivo que proporciona el usuario
        File bmp = null;
        String outFileName = null, stegAlg = null;
        // Estos parametros son obligatorios
        if(cmd.hasOption("p") && cmd.hasOption("out") && cmd.hasOption("steg")) {
            // Agarramos el nombre del archivo de output
            outFileName = cmd.getOptionValue("out");
            // Agarramos el metodo de esteganografiado
            stegAlg = cmd.getOptionValue("steg");
            // Verificamos que hayan puesto un algoritmo de esteganografiado valido
            if(!stegAlg.toLowerCase().equals("lsb1") && !stegAlg.toLowerCase().equals("lsb4") && !stegAlg.toLowerCase().equals("lsbi"))
                throw new RuntimeException("El algoritmo de esteganografiado proporcionado no es valido");
            // Agarramos el archivo BMP
            bmp = new File(cmd.getOptionValue("p"));
            // Verificamos el archivo BMP sea correcto segun documentacion y enunciado
            try { validateBMP(bmp); } catch (IOException e) { throw e; }
        }else{
            throw new RuntimeException("Faltan parametros");
        }


        // EXTRACCION
        if(cmd.hasOption("extract") || cmd.hasOption("ex")) {

            System.out.println("(2) -- Empezando con el proceso de extraccion");

            String pass = null, a = null, m = null;
            if(cmd.hasOption("pass")){
                pass = cmd.getOptionValue("pass");
                // Obtenemos el algoritmo de cifrado
                if(cmd.hasOption("a"))
                    a = cmd.getOptionValue("a");
                else
                    throw new RuntimeException("El algoritmo de cifrado proporcionado no es valido");
                // Obtenemos el metodo de encadenamiento
                if(cmd.hasOption("m"))
                    m = cmd.getOptionValue("m");
                else
                    throw new RuntimeException("El metodo de encadenamiento proporcionado no es valido");
            }
            // Creamos el File del archivo de salida en el que dejaremos el contenido extraido
            StegoBMP.extract(bmp, outFileName, stegAlg, pass, a, m);
        }
        else if(cmd.hasOption("embed") || cmd.hasOption("em")) {

            System.out.println("(2) -- Empezando con el proceso de ocultamiento");

            // En el caso que el payload este encriptado buscamos
            // la contrasenia, el algoritmo de encriptacion y el
            // metodo de encadenamiento
            String pass = null, a = null, m = null;

            File fileToHide;

            if(cmd.hasOption("in")) {
                fileToHide = new File(cmd.getOptionValue("in"));
            }else{
                throw new RuntimeException("El archivo a ocultar no es valido");
            }

            if(cmd.hasOption("pass")){
                pass = cmd.getOptionValue("pass");
                // Obtenemos el algoritmo de cifrado
                if(cmd.hasOption("a"))
                    a = cmd.getOptionValue("a");
                else
                    a = "aes128";
//                    throw new RuntimeException("El algoritmo de cifrado proporcionado no es valido");
                // Obtenemos el metodo de encadenamiento
                if(cmd.hasOption("m"))
                    m = cmd.getOptionValue("m");
                else
                    m = "cbc";
//                    throw new RuntimeException("El metodo de encadenamiento proporcionado no es valido");
            }
            // Creamos el File del archivo de salida en el que dejaremos el contenido extraido
            StegoBMP.embed(fileToHide, bmp, outFileName, stegAlg, pass, a, m);
        }

    }

    static void validateBMP(File bmp) throws IOException {
        // Usamos FileInputStream porque queremos acceder a los bytes del archivo
        FileInputStream stream = new FileInputStream(bmp);
        byte[] bytes = new byte[BMP_HEADER_SIZE];
        // Nos copiamos el header del BMP
        stream.read(bytes);
        // Chequeamos que el archivo este correcto
        // La info de esto esta aca: https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader?redirectedfrom=MSDN
        // Nos fijamos que los primeros dos bytes sean el string 'BM'
        if(bytes[0] != 0x42 && bytes[1] != 0x4D) {
            throw new RuntimeException("El archivo proporcionado no es un archivo BMP.");
        }
        // Nos fijamos que tengamos 3 bytes por pixel (enunciado)
        if(bytes[28] != 24) {
            throw new RuntimeException("El BMP debe tener 3 bytes por pixel.");
        }
        // El archivo no debe tener compresion (enunciado)
        if(bytes[30] != 0) {
            throw new RuntimeException("El BMP no debe tener compresion.");
        }
        // Si llegamos aca esta todo bien
        System.out.println("(1) -- Archivo BMP cargado con exito");
    }

    private static int getBitAtPos(byte currentByte, int position){
        return ((currentByte & (1 << position)) >> position) == 1 ? 1 : 0;
    }

}
