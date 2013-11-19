set terminal pngcairo
set output "imgs/times.png"
set ylabel "Caudal (Unidades)"
set boxwidth 0.5
set style data histogram
set xtics nomirror rotate by -45 scale 0 font ",8"
plot "arrivals" using ($0):1:($0):xticlabels(2) w boxes lc variable notitle