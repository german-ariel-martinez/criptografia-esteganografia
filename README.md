# criptografia-esteganografia

Proyecto realizado en Java con el objetivo de ocultar y extraer mensajes de archivos bmp
a traves de los metodos de esteganografia LSB1, LSB4 y LSBI planteado en este [paper](https://www.jatit.org/volumes/Vol80No2/16Vol80No2.pdf).


## Ejecución

### Ocultar
Para ejecutar el programa con el fin de esteganografiar un mensaje dentro de un archivo bmp, se
debe ejecutar el Main.java con los siguientes argumentos:
```
-embed -in <file_to_hide> -p <where_to_hide_bmp> -out <output_bmp_file> -steg <LSB1|LSB4|LSBI> 
```
Para ademas encriptar el mensaje se debe ejecutar con el argumento pass:
```
-embed -in <file_to_hide> -p <where_to_hide_bmp> -out <output_bmp_file> -steg <LSB1|LSB4|LSBI> -pass <password> [-a <aes128|aes192|aes256|des>] [-m <cbc|ecb|cfb|ofb>] 
```

### Extraer
Para ejecutar el programa con el fin de extraer un mensaje oculto de un archivo bmp, se
debe ejecutar el Main.java con los siguientes argumentos:

```
-extract -p <carrier_file_bmp> -out <output> -steg <LSB1|LSB4|LSBI>
```

En el caso de que se cuente con una password para desencriptar, se debe ejecutar:
```
-extract -p <carrier_file_bmp> -out <output> -steg <LSB1|LSB4|LSBI> -pass <password> -a <aes128|aes192|aes256|des> -m <cbc|ecb|cfb|ofb>
```