set terminal pngcairo
set output "imgs/times.png"
set ylabel "Caudal (Unidades)"

set style data histogram
set xtics nomirror rotate by -45 scale 0 font ",8"
plot for [COL=2:2] 'arrivals' using COL:xticlabels(1) title columnheader
