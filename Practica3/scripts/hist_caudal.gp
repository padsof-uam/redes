#Definición de cosas útiles
set terminal pngcairo
set output "imgs/throughput.png"
set xlabel "Tiempo (s)"
set ylabel "Número de paquetes"
set style fill solid 0.5

Column_number = 50

bin_width = 1
rounded(x) = bin_width * ( bin_number(x) + 0.5 )
bin_number(x) = floor(x/bin_width)
set xrange[0:]
set boxwidth 0.8*bin_width

plot 'throughput.dat' smooth frequency with boxes