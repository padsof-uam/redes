#Definición de cosas útiles
set terminal pngcairo
set output "imgs/arrivals_port.png"
set xlabel "Tiempo"
set ylabel "Número de paquetes"
set style fill solid 0.5

#Eliminaremos el valor más alto (que es lo que tarda en llegar el primer paquete que pase el filtro que normalmente será un valor demasiado alto)
xmax=system("sort -nk 1 arrivals | tail -n 2 | awk '{print $1}' | head -n 1")
set xrange [0:xmax]

Column_number = 40
bin_width = xmax/Column_number

rounded(x) = bin_width * ( bin_number(x) + 0.5 )
bin_number(x) = floor(x/bin_width)

set boxwidth 0.8*bin_width

plot 'arrivals' using (rounded($1)):(1) smooth frequency with boxes