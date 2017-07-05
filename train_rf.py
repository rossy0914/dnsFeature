import argparse
import timeit
import os
import numpy as np
import pandas as pd
import xgboost
import math
from scipy.stats import kurtosis,skew
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report

def getopt():
    parser = argparse.ArgumentParser(description='train convolutioned csv file with RF')
    parser.add_argument("train_csv")
    parser.add_argument("test_csv")
    

    args = parser.parse_args()
    return args

def sklearn_train(train,test):

    fw_cor = open('./correct_kurt.txt','a')
    fw_unk = open('./unknown_kurt.txt','a')
    fw_wrg = open('./wrong_kurt.txt','a')

    train_df = pd.DataFrame(pd.read_csv(train,low_memory=False))    
    test_df = pd.DataFrame(pd.read_csv(test,low_memory=False))
    
    print("Label encoding...")
    ip_le = LabelEncoder()
    all_class = list()
    for col in train_df.columns.values:
        if train_df[col].dtypes == 'object':
            #print(col)
            le = LabelEncoder()
            data = train_df[col].append(test_df[col])
            le.fit(data.values)
            train_df[col] = le.transform(train_df[col])
            test_df[col] = le.transform(test_df[col])
            if col == 'ip':
                ip_le = le
                all_class = le.transform(np.unique(data))
 
    feature_name = ["qryNum","ansNum","qryType","rcode","respPktSize","domNameLen","respTime",\
        "success","nxDomain","distASN","distCountry","distNet","meanTTL","stdTTL","distTTL","totalTTL","TTL0","TTL1","TTL10","TTL100","TTL300","TTL900up",\
        "distanceBtwIP","entTimezone",\
        "qryType Seq","rcode Seq","success Seq","NXDomain Seq","period","hour","ip"]
    X_train = np.array(train_df[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28]])
    y_train = np.array(train_df['ip'])
    X_test = np.array(test_df[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28]])
    y_test = np.array(test_df['ip'])
   
    train_class = list(np.unique(y_train))
    test_class = list(np.unique(y_test))
    print(train_class)
    print("train class len:",len(train_class))
    print(test_class)
    print("test class len:",len(test_class))
    print("all class:",all_class)

    for i in train_class:
        if i in test_class:
            print(ip_le.inverse_transform([i])[0]," ",i,": ",len(y_train[y_train == i]),'\t',len(y_test[y_test == i]))
        else:
            print(ip_le.inverse_transform([i])[0]," ",i,": ",len(y_train[y_train == i]),'\t',"-")
            

    rf_clf = RandomForestClassifier(n_estimators=100,criterion = 'gini',warm_start = 'True')
    print("Fitting random forest...")
    rf_clf = rf_clf.fit(X_train, y_train)
    print("parameters: ",rf_clf.get_params())
    score = rf_clf.score(X_test, y_test)
    print("Score: ", score)
    
    importances = rf_clf.feature_importances_
    std = np.std([tree.feature_importances_ for tree in rf_clf.estimators_], axis=0)
    indices = np.argsort(importances)[::-1]

    # Print the feature ranking
    print("Feature ranking:")

    for f in range(X_train.shape[1]):
        print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))
    y_predict = rf_clf.predict(X_test)
    #print(y_predict)
    #y_test = ip_le.inverse_transform(y_test)
    #y_predict = ip_le.inverse_transform(y_predict)
    print(classification_report(y_test,y_predict))
    '''
    probs = pd.DataFrame(rf_clf.predict_proba(X_test))
    print("all probabilities:\n", probs, "\n")
    for c in range(len(test_class)):
        likely=probs[probs[c] > 0.5]
        #print("class" + str(c) + " probability > 0.5:\n", likely)
        print("indexes of likely class" + str(c) + ":", likely.index.tolist(), "\n")
    '''
    pred_m =  confusion_matrix(y_test,y_predict,labels = all_class)
    pred_r = map(list,zip(*pred_m))
    print(pred_m)
    #print(pred_r)
    #print(pred_m.shape)
    #print(pred_m.argmax(axis=1))

    i = 0 
    kurt_list = list()
    cor = list()
    wrg = list()
    unk = list()
    uns = 0
    
    for p, q in zip(pred_m,pred_r):
        kurt = kurtosis(p)
        kurt_r = kurtosis(q)
        prob = p / sum(p)
        prob_r = q / sum(q)
        #print(prob)
        kurt_prob = kurtosis(prob)
        kurt_prob_r = kurtosis(prob_r)
        skew_prob = skew(prob)
        if math.isnan(kurt_prob):
            kurt_list.append((kurt_prob,kurt_prob_r,-1,max(prob)))
        else:
            kurt_list.append((kurt_prob,kurt_prob_r,p.argmax(),max(prob)))
        #print(i,": ",kurt_r,kurt_prob_r,kurt_prob,skew_prob,", max:",p.argmax(),max(prob)) 
        i += 1
    
    k_norm = list()
    k_r_norm = list()
    weight_cor = 0
    weight_conf = 0
    conf_cor = 0
    conf_wrg = 0
    conf_unk = 0
    unconf = 0
    deter_cor = 0
    deter_wrg = 0
    deter_unk = 0
    undeter = 0
    kurt_max = max(kurt_list,key=lambda item:item[0])[0]
    kurt_min = min(kurt_list,key=lambda item:item[0])[0]
    kurt_r_max = max(kurt_list,key=lambda item:item[1])[1]
    kurt_r_min = min(kurt_list,key=lambda item:item[1])[1]
    
    clf_label = dict()
    conf_label = dict()

    for label in all_class:
        k = kurt_list[label]
        label_ip = ip_le.inverse_transform([label])[0]
        #print("label:",label," ip:",ip_le.inverse_transform([label])[0])
        k_norm.append(k[0]/kurt_max)
        k_r_norm.append(k[1]/kurt_r_max)
        if k[0] > -3:  
            if label not in test_class:
                tag = 'no test'
                ratio = float('inf')
                log_ratio = 1
            elif label not in train_class and label in test_class: 
                tag = 'unknown'
                ratio = 0
                log_ratio = float("-inf")
                unk.append(k_norm[label])
                fw_unk.write(str(k_norm[label])+'\t'+str(k_r_norm[label])+'\t'+str(k[2])+'\n')   
            elif label == k[2]:
                tag = 'correct'
                ratio = len(y_train[y_train == label])/len(y_test[y_test == label])
                log_ratio = math.log10(ratio)
                weight_cor += len(y_test[y_test == label])/len(y_test)
                cor.append((label,k_norm[label]))
                fw_cor.write(str(k_norm[label])+'\t'+str(k_r_norm[label])+'\t'+str(k[2])+'\n')
            else:
                tag = 'wrong'
                ratio = len(y_train[y_train == label])/len(y_test[y_test == label])
                log_ratio = math.log10(ratio)
                wrg.append((label,k_norm[label]))
                fw_wrg.write(str(k_norm[label])+'\t'+str(k_r_norm[label])+'\t'+str(k[2])+'\n')
            if (k_norm[label]) > 0.8 :
                print(label_ip,'belongs to user ',k[2],k_norm[label],'max prob=',k[3],'\t',"confident")
                clf_label[label_ip] = ip_le.inverse_transform(k[2])[0]
                conf_label[label_ip] = ip_le.inverse_transform(k[2])[0]
                if tag == 'correct':
                    conf_cor += 1
                    weight_conf += len(y_test[y_test == label])/len(y_test)
                elif tag == 'wrong':
                    conf_wrg += 1
                elif tag == 'unknown':
                    conf_unk += 1
            elif (k_r_norm[label]) < 0.5:
                print(label_ip,'belongs to user ',k[2],k_norm[label],'max prob=',k[3],'\t',"undetermined")
                clf_label[label_ip] = ip_le.inverse_transform(k[2])[0]
                unconf += 1
                undeter+=1
            else:
                print(label_ip,'belongs to user ',k[2],k_norm[label],'max prob=',k[3],'\t',"probably unknown")
                clf_label[label_ip] = ip_le.inverse_transform(k[2])[0]
                unconf+=1
                if tag == 'correct':
                    deter_cor += 1
                elif tag == 'wrong':
                    deter_wrg += 1
                elif tag == 'unknown':
                    deter_unk += 1
                    weight_conf += len(y_test[y_test == label])/len(y_test)
            #print(label_ip,' belongs to user ',k[2],',it\'s kurtosis=',k_norm[label],',it\'s max prob=',k[3],'\t')
        else:
            print(label, "not in testing set")
            uns += 1
    
    print("unknown(not in training set): ",len(unk),", consists ",100*len(unk)/len(test_class),"% of testing class")
    print("not in testing set:", uns,", consists ",100*uns/len(train_class),"% of training class")
    print("correct:",len(cor))
    print("wrong:",len(wrg))
    print("unknown:",len(unk))
    print("conf_cor:",conf_cor,"conf_wrg",conf_wrg,"conf_unk",conf_unk)
    print("deter_cor:",deter_cor,"deter_wrg",deter_wrg,"deter_unk",deter_unk)
    print()
    print("acc of all known label:",len(cor)/(len(cor)+len(wrg)))
    print("acc of determined label:",(conf_cor+deter_unk)/(conf_cor+conf_unk+conf_wrg+deter_cor+deter_wrg+deter_unk))
    print("acc of weighted label:",weight_cor)
    print("acc of weighted label in conf test:",weight_conf)
    print()
    print("confidence test acc:",(conf_cor+deter_unk+(len(wrg)-conf_wrg-deter_wrg))/len(test_class))
    print("correct|known:",conf_cor/(len(test_class)-len(unk)))
    #print("correct|unknown:",deter_unk/len(unk))
    #print("undetermined found:",(len(wrg)-conf_wrg-deter_wrg)/len(wrg))
    print()
    print("confident % in correct:",conf_cor/len(cor))
    #print("confident % in wrong:",conf_wrg/len(wrg))
    #print("confident % in unknown:",conf_unk/len(unk))
    #print("correct % in not confident",(len(cor)-conf_cor)/unconf)
    #print("wrong % in not confident",(len(wrg)-conf_wrg)/unconf)
    #print("unknown % in not confident",(len(unk)-conf_unk)/unconf)
    
    result_df = pd.DataFrame(np.concatenate((y_test, y_predict.T), axis=1),columns=feature_name)
    for ip in clf_dict:
        result_df[result_df['ip']==ip]['ip'] = clf_dict[ip]
    

    print("----------")

    fw_cor.close()
    fw_unk.close()
    fw_wrg.close()

def main():
    
    time1 = timeit.default_timer()
    
    args = getopt()
    dname = args.train_csv.rsplit('.csv')[0].split('/')[-1]
    
    '''
    for ip in [10,11,12,13,14,15,25,28,29,3,4,9]:
        sklearn_train(args.train_csv,args.test_csv,ip)
    '''
    sklearn_train(args.train_csv,args.test_csv)
    
    time2 = timeit.default_timer()
    
    print("Total time cost: ", time2-time1)

if __name__ == "__main__":
    main()
