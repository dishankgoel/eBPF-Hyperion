import React, { useEffect, useState } from 'react';
import { LineChart, XAxis, YAxis, CartesianGrid, Line, ResponsiveContainer, Legend } from 'recharts';

const App = () => {

  const [msg, setMsg] = useState('');
  const [perfdata, setPerfdata] = useState([]);
  const [maxperflen, setMaxperflen] = useState(10);
  const [finaldata, setFinaldata] = useState({'a': []});

  useEffect(() => {
    var ws = null;
    ws = new WebSocket("ws://localhost:8000/ws");
    // ws.onopen = () => ws.send("Connected to React!");
    ws.onmessage=(e) => {
      // console.log("Accepted Message: ", e.data);
      setMsg(e.data);
      console.log("e.data: ", e.data);

      setPerfdata(currentData => [...currentData, JSON.parse(e.data)]);
      // console.log("lasan");

      var json_data = JSON.parse(e.data);

      // var tmp_map = {}
      // for(var key in json_data.cont_data){
      //   tmp_map[key] = [...finaldata[key], json_data.cont_data.key]
      // }
      // setFinaldata(tmp_map);

      // perfdata.filter(x => x.cont_data.a === 'a');
    };

    // console.log("perfdata: ", perfdata);
  }, []);

  useEffect(()=>
  {
    console.log("datanew",perfdata);
    if(perfdata.length === maxperflen){
      var tmp_data = perfdata;
      tmp_data.shift();
      setPerfdata(tmp_data);
    }
  },[perfdata,]);

  useEffect(() => {
    console.log("finaldata: ", finaldata);
  }, [finaldata,]);

  var data_new = [
    {
      "cnt": 1,
      "a": 2,
      "b": 3
    },
    {
      "cnt": 2,
      "a": 4,
      "b": 2
    },
    {
      "cnt": 3,
      "a": 1,
      "b": 3
    },
    {
      "cnt": 4,
      "a": 1,
      "b": 6
    },
    {
      "cnt": 5,
      "a": 5,
      "b": 2
    },
  ];

  var tmp = [];

  var cont_datas = {}

  // for()

  return (
    <div>
      172.17.0.3
      <br />

      {/* <ResponsiveContainer width={1000} aspect={3} key={Math.random()}> */}
        <LineChart width={500} height={300} data={perfdata}>
        <XAxis dataKey="timestamp"/>
        <YAxis/>
        {/* <Legend/> */}
        <CartesianGrid stroke="#eee" strokeDasharray="5 5"/>
        <Line type="monotone" dataKey="cont_data.2886795267.tcp_counter" stroke="#8884d8" isAnimationActive={false}/>
        <Line type="monotone" dataKey="cont_data.2886795267.total_counter" stroke="#82ca9d" isAnimationActive={false}/>
      </LineChart>
      {/* </ResponsiveContainer> */}

      172.17.0.2
      <br />
        <LineChart width={500} height={300} data={perfdata}>
        <XAxis dataKey="timestamp"/>
        <YAxis/>
        {/* <Legend/> */}
        <CartesianGrid stroke="#eee" strokeDasharray="5 5"/>
        <Line type="monotone" dataKey="cont_data.2886795266.tcp_counter" stroke="#8884d8" isAnimationActive={false}/>
        <Line type="monotone" dataKey="cont_data.2886795266.total_counter" stroke="#82ca9d" isAnimationActive={false}/>
      </LineChart>


    </div>
  )
}

export default App
