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
  L = []
  a = struct.unpack("i",f.read(4))
  nbins = a[0]
  num_samples = (file_length_in_bytes/4) - 1
  for t in range (0, num_samples):
    x = struct.unpack("i",f.read(4))
    L.append(x[0])
  f.close

  sys.stdout.write("\nNumber of bins: " + str(nbins) + ", number of samples: ")
  print(num_samples)

  title= 'frequency bins ' + str(num_samples) + ' samples'
  xlabel='differnce'
  ylabel='relative freq'

  xlist = []
  ylist = []

  bins = []

  for i in range (0, nbins):
    bins.append(0)

  for l in range (0, len(L)):
    i = L[l]
    bins[i] = bins[i] + 1

  rel_bins = []
  for i in range (0, len(bins)):
    rel_bins.append(float(bins[i]/float(num_samples)))

  for i in range (0, len(rel_bins)):
    xlist.append(i)
    ylist.append(rel_bins[i])

  left = -1
  right = 16
  top = 1
  bottom = 0

  plt.title(title)
  plt.xlabel(xlabel)
  plt.ylabel(ylabel)
  plt.axes().set_aspect('auto')
  plt.axis([left, right, bottom, top])
  plt.plot(xlist, ylist)
  plt.savefig(outputfile)
  plt.show()

main(sys.argv)


  
