#!/usr/bin/python3
# _*_ coding:utf-8 _*_

import tensorflow as tf
import numpy as np
import apriori_permission as apriori
import pandas as pd

csv_path = 'permission.csv'          # permission.csv : The dataset from internet containing 199 malware and 199 benign APKs.

def load_data():
    df = pd.read_csv(csv_path,  sep=';')
    prmissions = apriori.apriori_select(df,min_support=0.2, min_confidence=0.8)
    x_train = np.array(df[prmissions])
    y_train = np.array(df['type'])
    y_label = np.array([[x] for x in y_train])
    return x_train,y_label

if __name__ == "__main__":
    x_train,y_label = load_data()
    regularizer = tf.contrib.layers.l2_regularizer(0.1, scope=None)
    w1 = tf.get_variable('w1',shape=[9,3],initializer=tf.random_normal_initializer,regularizer=regularizer)
    w2 = tf.get_variable('w2',shape=[3,1],initializer=tf.random_normal_initializer,regularizer=regularizer)
    b1 = tf.get_variable('b1',initializer=tf.constant([0.]))
    b2 = tf.get_variable('b2',initializer=tf.constant([0.]))
    
    input = tf.placeholder(tf.float32,shape=(None,9),name="input")
    label = tf.placeholder(tf.float32,shape=(None,1),name="label")
    # FP
    a = tf.nn.sigmoid(tf.matmul(input,w1)+b1)
    output = tf.nn.sigmoid(tf.matmul(a,w2)+b2,name="output")

    cross_entropy = tf.reduce_mean(tf.nn.sigmoid_cross_entropy_with_logits(logits=output, labels=label))
    train_step = tf.train.AdamOptimizer(0.0001).minimize(cross_entropy)

    #saver = tf.train.Saver()

    with tf.Session() as sess:
        init = tf.global_variables_initializer()
        sess.run(init)

        # Set the number of iterations of the neural network
        steps = 301
        # Stochastic gradient descent
        for i in range(steps):
	        if i == 301:
	            break;          
            for (input_x, input_y) in zip(x_train, y_label):

                input_x = np.reshape(input_x, (1, 9))
                input_y = np.reshape(input_y, (1, 1))
                
                sess.run(train_step, feed_dict={input: input_x, label: input_y})

            # Output log information 100 times per iteration
            if i % 100 == 0:
                # Calculate the cross entropy of all data
                total_cross_entropy = sess.run(cross_entropy, feed_dict={input: x_train, label: y_label})
                print("After %d training step(s),cross entropy on all data is %g" % (i, total_cross_entropy))

        # Save the .tflite model
        # converter = tf.contrib.lite.TocoConverter.from_session(sess, [input], [output])
        # tflite_model = converter.convert()
        # open("permission_model_from_session.tflite", "wb").write(tflite_model)

        # Predict
        pred_Y = sess.run(output, feed_dict={input: x_train})

        for pred, real in zip(pred_Y, y_label):
            print(pred, real)
