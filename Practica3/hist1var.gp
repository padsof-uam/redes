bin_width = 1
rounded(x) = bin_width * ( bin_number(x) + 0.5 )
bin_number(x) = floor(x/bin_width)
plot 'sizes' using (rounded($1)):(1) smooth frequency with boxes