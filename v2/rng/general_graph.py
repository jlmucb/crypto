#!/usr/bin/python
import sys, getopt
from matplotlib.pyplot import plot, show
import matplotlib.pyplot as plt

class Coords:
  def __init__(self, x, y):
    self.x = x
    self.y = y

def main(argv=sys.argv):
  inputfile = sys.argv[1]
  outputfile = sys.argv[2]

  import os
  import struct
  file_length_in_bytes = os.path.getsize(inputfile)

  f = open(inputfile, mode='rb')
  num_samples = 0
  a = struct.unpack("i",f.read(4))
  num_points = a[0]

  x = []
  y = []
  for t in range (0, num_points):
    b = struct.unpack("d", f.read(8))
    c = struct.unpack("d", f.read(8))
    x.append(b[0])
    y.append(c[0])

  x_min = 0.0
  x_max = 0.0
  y_min = 0.0
  y_max = 0.0
  for t in range (0, num_points):
    if (t == 0) :
      x_min = x[0]
      x_max = x[0]
      y_min = y[0]
      y_max = y[0]
    if (x[t] < x_min):
      x_min = x[t]
    if (x[t] > x_max):
      x_max = x[t]
    if (y[t] < y_min):
      y_min = y[t]
    if (y[t] > y_max):
      y_max = y[t]
  f.close

  sys.stdout.write("\nNumber of points: " + str(num_points) + "\n")

  for i in range (0, num_points):
    sys.stdout.write("  (" + str(x[i]) + ", " + str(y[i]) + ")\n")

  left = x_min
  right = x_max
  top = y_max
  bottom = y_min

  title= 'graph, ' + str(num_points) + ' points'
  xlabel='x'
  ylabel='y'

  plt.title(title)
  plt.xlabel(xlabel)
  plt.ylabel(ylabel)
  plt.axes().set_aspect('auto')
  plt.axis([left, right, bottom, top])
  plt.plot(x, y)
  plt.savefig(outputfile)
  plt.show()

main(sys.argv)


  
