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
  bins = []
  num_samples = 0
  a = struct.unpack("i",f.read(4))
  nbins = a[0]
  for t in range (0, nbins):
    x = struct.unpack("i",f.read(4))
    bins.append(x[0])
    num_samples = num_samples + x[0]
  f.close

  sys.stdout.write("\nNumber of bins: " + str(nbins) + ", number of samples: ")
  print(num_samples)

  rel_bins = []
  for i in range (0, len(bins)):
    rel_bins.append(float(bins[i]/float(num_samples)))

  xlist = []
  ylist = []

  for i in range (0, len(rel_bins)):
    xlist.append(i)
    ylist.append(rel_bins[i])

  left = -1
  right = nbins
  top = .25
  bottom = 0

  title= 'frequency bins, ' + str(num_samples) + ' samples'
  xlabel='difference'
  ylabel='relative freq'

  plt.title(title)
  plt.xlabel(xlabel)
  plt.ylabel(ylabel)
  plt.axes().set_aspect('auto')
  plt.axis([left, right, bottom, top])
  plt.plot(xlist, ylist)
  plt.savefig(outputfile)
  plt.show()

main(sys.argv)


  
