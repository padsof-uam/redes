set terminal pngcairo
set output "imgs/times.png"
set ylabel "Caudal (Unidades)"
set boxwidth 0.8
set style data histogram
set xrange[0:]
set yrange[0:]

set xtics nomirror rotate by -45 scale 0 font ",8"
bin_width = 0.05
set boxwidth 0.5*bin_width
set style fill solid 0.5
rounded(x) = bin_width * ( bin_number(x) + 0.5 )
bin_number(x) = floor(x/bin_width)
plot 'arrivals.dat' using ($2):xticlabels(1) w boxes 
